import os
import re
import io
import hmac
import json
import time
import uuid
import queue
import random
import base64
import sqlite3
import secrets
import hashlib
import calendar
import requests
import smtplib
import unicodedata
import datetime as dt

from uuid import uuid4
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone, timedelta

import resend
import mammoth

from PIL import Image, UnidentifiedImageError

from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from flask import (
    Flask, request, redirect, url_for, flash, render_template,
    session, abort, current_app, jsonify, Response,
    stream_with_context, has_request_context, g
)

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)

from sqlalchemy import text, case, or_, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.types import TypeDecorator, String as SAString

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from slugify import slugify
from docx import Document
from docx.oxml.ns import qn




def _to_utc_aware(dt):
    """Đưa datetime về timezone-aware UTC để so sánh an toàn."""
    if not dt:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

VN_TZ = timezone(timedelta(hours=7))

def now_vn():
    return datetime.now(VN_TZ)

def add_months_exact(dt_value, months):
    """
    Cộng đúng số tháng theo lịch.
    Ví dụ:
    06/03 + 3 tháng = 06/06
    31/01 + 1 tháng = 28/02 hoặc 29/02
    """
    

    months = max(1, int(months or 1))

    year = dt_value.year
    month = dt_value.month + months

    year += (month - 1) // 12
    month = ((month - 1) % 12) + 1

    day = min(dt_value.day, calendar.monthrange(year, month)[1])

    return dt_value.replace(year=year, month=month, day=day)

def is_user_membership_active(user):
    end = _to_utc_aware(user.trial_end) if getattr(user, "trial_end", None) else None
    now = _to_utc_aware(now_vn())
    return bool(end and end > now)

def get_pending_change_type(user, new_plan_code: str):
    """
    return:
      - expired_renew: đã hết hạn, giờ mua lại
      - same_plan_extend: còn hạn, gia hạn cùng gói
      - upgrade_or_downgrade: còn hạn, đổi sang gói khác
    """
    current_plan = norm_plan(getattr(user, "member", None) or "FREE")
    new_plan_code = norm_plan(new_plan_code)

    if not is_user_membership_active(user):
        return "expired_renew"

    if current_plan == new_plan_code:
        return "same_plan_extend"

    return "upgrade_or_downgrade"

def vn_filename(text: str) -> str:
    """'Đỡ hạ' -> 'do_ha' """
    s = (text or "").strip().lower()
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")  # bỏ dấu
    s = s.replace("đ", "d")
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "lesson"



def split_docx_by_page(docx_path):
    doc = Document(docx_path)

    pages = []
    current = []

    for para in doc.paragraphs:

        # ==== CHECK PAGE BREAK KIỂU 1: run <w:br type="page">
        has_page_break = False
        for run in para.runs:
            for br in run._element.findall(qn("w:br")):
                if br.get(qn("w:type")) == "page":
                    has_page_break = True

        # ==== CHECK PAGE BREAK KIỂU 2: <w:pageBreakBefore/>
        pPr = para._element.pPr
        if pPr is not None and pPr.find(qn("w:pageBreakBefore")) is not None:
            has_page_break = True

        if has_page_break:
            pages.append("\n".join(current))
            current = []
            continue

        current.append(para.text)

    if current:
        pages.append("\n".join(current))

    return pages

def migrate_add_pdf_to_lessons():
    lesson_dir = os.path.join(app.instance_path, "lessons")
    static_root = app.static_folder

    for f in os.listdir(lesson_dir):
        if not f.endswith(".json"):
            continue

        path = os.path.join(lesson_dir, f)
        with open(path, "r", encoding="utf-8") as jf:
            data = json.load(jf)

        slug = data.get("slug")
        if not slug:
            continue

        # Ưu tiên PDF theo slug
        pdf_slug = os.path.join(static_root, "lessons", f"{slug}.pdf")
        pdf_default = os.path.join(static_root, "Bai_hoc.pdf")

        if os.path.isfile(pdf_slug):
            data["pdf"] = f"lessons/{slug}.pdf"
        elif os.path.isfile(pdf_default):
            data["pdf"] = "Bai_hoc.pdf"
        else:
            data["pdf"] = None   # ✅ KHÔNG ÉP

        data["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(path, "w", encoding="utf-8") as jf:
            json.dump(data, jf, ensure_ascii=False, indent=2)


def slugify(text):
    # xử lý riêng cho đ/Đ
    text = text.replace("đ", "d").replace("Đ", "D")

    # bỏ dấu tiếng Việt
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")

    # thay ký tự lạ bằng _
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text)

    return text.strip("_").lower()

def get_lesson_json_path(slug):
    base = os.path.join(current_app.instance_path, "lessons")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, f"{slug}.json")



app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SECRET_KEY"] = "KEN_TAEKWONDO_2026"
os.makedirs(app.instance_path, exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "quiz.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
datetime.now(timezone.utc)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# ===== UPLOAD CONFIG =====
UPLOAD_ROOT = os.path.join(app.root_path, "static", "uploads")

for i in (1, 2, 3):
    os.makedirs(os.path.join(UPLOAD_ROOT, f"folder{i}"), exist_ok=True)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev_secret_change_me")

BASE_URL = os.getenv(
    "BASE_URL",
    "https://phungtkdsystem.up.railway.app"
).rstrip("/")

def get_base_url():
    if has_request_context():
        return request.host_url.rstrip("/")
    return BASE_URL

LOGO_URL = f"{BASE_URL}/static/logo.jpg"

# ==============================
# JINJA FILTER: MASK EMAIL (REGISTER EARLY)
# ==============================
def mask_email(value, keep: int = 5):
    if not value:
        return ""
    s = str(value).strip()
    if len(s) <= keep:
        return s
    return s[:keep] + ("*" * (len(s) - keep))

app.jinja_env.filters["mask_email"] = mask_email


ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "silentnight1993pro@gmail.com").strip()

PLAN_PRICES = {
    "BASIC": 300_000,
    "PRO": 500_000,
    "VIP": 800_000
}

def norm_plan(code: str) -> str:
    c = (code or "").strip().upper()
    if c in ("FREE", "BASIC", "PRO", "VIP", "ADMIN"):
        return c
    return "FREE"

def plan_display(code: str) -> str:
    c = norm_plan(code)
    return {
        "FREE":  "Taekwondo Free",
        "BASIC": "Taekwondo Cơ Bản",
        "PRO":   "Taekwondo Nâng cao",
        "VIP":   "Taekwondo Cao Cấp",
    }.get(c, "Taekwondo Free")



def to_naive_utc(dt):
    if not dt:
        return None

    # Nếu dt có timezone -> đổi về UTC rồi bỏ tzinfo
    if dt.tzinfo is not None and dt.utcoffset() is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)

    # Nếu dt đã là naive thì giữ nguyên
    return dt

def calc_totals(plan_code: str, months: int):
    plan = norm_plan(plan_code)
    months = max(1, int(months or 1))

    price_map = {
        "FREE":  0,
        "BASIC": 300_000,
        "PRO":   500_000,
        "VIP":   800_000,
    }
    price = price_map.get(plan, 0)

    # discount rate
    rate = 0.0
    if months == 3: rate = 0.10
    elif months == 6: rate = 0.15
    elif months == 12: rate = 0.20

    raw_total = price * months
    discount = round(raw_total * rate)
    final_total = raw_total - discount
    return price, raw_total, discount, final_total, rate

def fmt_vnd(n: int) -> str:
    n = int(n or 0)
    return f"{n:,}".replace(",", ".") + " VNĐ"



def migrate_user_table():
    """Auto-add missing columns in SQLite table `user`."""
    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
    if not uri.startswith("sqlite"):
        return

    with app.app_context():
        cols = db.session.execute(text("PRAGMA table_info(user)")).fetchall()
        existing = {c[1] for c in cols}

        def add(col_sql: str, name: str):
            if name not in existing:
                db.session.execute(text(f"ALTER TABLE user ADD COLUMN {col_sql}"))
                db.session.commit()
                existing.add(name)

        add("pending_member TEXT", "pending_member")
        add("pending_member_name TEXT", "pending_member_name")
        add("pending_plan_code TEXT", "pending_plan_code")

        add("pending_months INTEGER DEFAULT 0", "pending_months")
        add("pending_amount INTEGER DEFAULT 0", "pending_amount")
        add("pending_discount INTEGER DEFAULT 0", "pending_discount")
        add("pending_final_total INTEGER DEFAULT 0", "pending_final_total")

        add("pending_duration_label TEXT", "pending_duration_label")
        add("pending_memo TEXT", "pending_memo")
        add("pending_at TEXT", "pending_at")
        add("pending_approve_token TEXT", "pending_approve_token")

def migrate_notification_table():
    """Auto-add missing columns in SQLite table `notifications`."""
    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
    if not uri.startswith("sqlite"):
        return

    with app.app_context():
        cols = db.session.execute(text("PRAGMA table_info(notifications)")).fetchall()
        existing = {c[1] for c in cols}

        def add(col_sql: str, name: str):
            if name not in existing:
                db.session.execute(text(f"ALTER TABLE notifications ADD COLUMN {col_sql}"))
                db.session.commit()
                existing.add(name)

        add("action_type TEXT", "action_type")
        add("ref_user_id INTEGER", "ref_user_id")
        add("ref_plan_code TEXT", "ref_plan_code")
        add("ref_months INTEGER", "ref_months")
        add("is_done INTEGER DEFAULT 0", "is_done")

def send_voucher_to_selected_users(promo_id: int):
    promo = PromotionCampaign.query.get(promo_id)
    if not promo:
        return

    links = PromotionUser.query.filter_by(promotion_id=promo.id).all()
    if not links:
        return

    for link in links:
        user = User.query.get(link.user_id)
        if not user:
            continue

        # 1) tạo thông báo trong hệ thống
        try:
            n = Notification(
                role="user",
                user_id=user.id,
                title=f"🎁 Bạn nhận được phiếu khuyến mãi: {promo.code}",
                message=(
                    f"Bạn vừa nhận được phiếu khuyến mãi.\n"
                    f"Mã: {promo.code}\n"
                    f"Tên: {promo.title}\n"
                    f"Gói áp dụng: {promo.plan_codes}\n"
                    f"Giảm: "
                    f"{str(promo.discount_value) + '%' if promo.discount_type == 'percent' else fmt_vnd(promo.discount_value)}\n"
                    f"Từ: {promo.start_at.strftime('%d/%m/%Y %H:%M') if promo.start_at else ''}\n"
                    f"Đến: {promo.end_at.strftime('%d/%m/%Y %H:%M') if promo.end_at else ''}\n\n"
                    f"Hãy nhập mã này tại ô 'Mã khuyến mãi' khi thanh toán."
                ),
                target_url=url_for("main"),
                icon="🎁",
                is_read=False,
                action_type="voucher_notice",
                ref_user_id=user.id,
                is_done=False,
                created_at=now_vn()
            )
            db.session.add(n)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("[send_voucher_to_selected_users][notification] ERROR:", e)

        # 2) gửi email nếu user có email
        if user.email:
            try:
                html = render_app_email(
                    subject_title="🎁 Bạn nhận được phiếu khuyến mãi",
                    preheader=f"Mã {promo.code} đã được gửi cho bạn.",
                    username=user.username,
                    message_html=f"""
                      <p>Xin chào <strong>{user.username}</strong>!</p>
                      <p>Bạn vừa nhận được một <strong>phiếu khuyến mãi riêng</strong>.</p>

                      <div style="margin:14px 0;padding:14px 16px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;line-height:1.8;">
                        <div><strong>Mã phiếu:</strong> {promo.code}</div>
                        <div><strong>Tên:</strong> {promo.title}</div>
                        <div><strong>Gói áp dụng:</strong> {promo.plan_codes}</div>
                        <div><strong>Giảm:</strong> {"{}%".format(promo.discount_value) if promo.discount_type == "percent" else fmt_vnd(promo.discount_value)}</div>
                        <div><strong>Hiệu lực từ:</strong> {promo.start_at.strftime('%d/%m/%Y %H:%M') if promo.start_at else ''}</div>
                        <div><strong>Đến:</strong> {promo.end_at.strftime('%d/%m/%Y %H:%M') if promo.end_at else ''}</div>
                      </div>

                      <p>Khi thanh toán gói học, vui lòng nhập mã này vào ô <strong>Mã khuyến mãi</strong> để được trừ thêm tiền.</p>
                    """,
                    button_text="Vào hệ thống học tập",
                    button_url=get_base_url(),
                    note_html=None
                )
                send_email(user.email, f"Phiếu khuyến mãi {promo.code}", html)
            except Exception as e:
                print("[send_voucher_to_selected_users][email] ERROR:", e)


def render_app_email(subject_title, preheader, username, message_html, button_text=None, button_url=None, note_html=None):
    return render_template(
        "base_email.html",
        title=subject_title,
        preheader=preheader,
        username=username,
        current_year=datetime.now().year,

        # giữ header/footer cũ của Ken
        brand_name="Hệ thống học tập Taekwondo",
        brand_url=BASE_URL,
        logo_url=LOGO_URL,
        header_right_text="",
        brand_address="TP.HCM, Việt Nam",
        support_email="silentnight1993pro@gmail.com",
        unsubscribe_url=None,

        # body động
        message_html=message_html,
        button_text=button_text,
        button_url=button_url,
        note_html=note_html
    )

def build_user_waitaccept_email(username, plan_code, months):
    user = User.query.filter_by(username=username).first()
    checkout = calc_plan_checkout_for_user(user, plan_code, months)

    raw_total = checkout["raw_total"]
    discount = checkout["discount"]
    final_total = checkout["final_total"]
    plan_name = checkout["plan"].name
    rate = 0
    if raw_total > 0:
        rate = discount / raw_total
    body = f"""
      <p style="margin:0 0 10px;"><strong>Xin chào, {username}!</strong></p>

      <p style="margin:0 0 12px;">
        Xin cảm ơn bạn đã tin tưởng và sử dụng hệ thống học tập Taekwondo.
      </p>

      <div style="
        margin:14px 0 14px;
        padding:14px 16px;
        background:#f9fafb;
        border:1px solid #e5e7eb;
        border-radius:12px;
        line-height:1.8;
      ">
        <div><strong>Bạn đã đăng ký gói:</strong> {plan_name} (<strong>{norm_plan(plan_code)}</strong>)</div>
        <div><strong>Số tháng đăng ký:</strong> {months}</div>
        <div style="margin-top:8px;"><strong>Số tiền:</strong> {fmt_vnd(raw_total)}</div>
        <div><strong>Giảm giá:</strong> -{fmt_vnd(discount)} ({int(rate*100)}%)</div>
        <div><strong>Thành tiền:</strong> {fmt_vnd(final_total)}</div>
      </div>

      <p style="margin:0 0 12px;">
        Xin vui lòng chờ Admin duyệt. Nếu quá <strong>24h</strong>, vui lòng liên hệ về:</p>
      <p style="margin:0 0 12px;"> <strong>Email:</strong> silentnight1993pro@gmail.com</p>
      <p style="margin:0 0 12px;"> <strong>Hotline:</strong> +84 989 03 04 93 </p>

      <p style="margin:0 0 8px;">
        Chúc bạn có những buổi học và ôn tập thật thú vị.
      </p>

      <p style="margin:0;">
        Xin vui lòng không được tiết lộ hoặc chia sẻ tên ID hoặc mật khẩu cho người khác,
        để tránh các trường hợp bị mất thông tin.
      </p>

      <p style="margin:10px 0 0;"><strong>Xin cảm ơn!</strong></p>
    """

    return render_app_email(
        subject_title="💳Xác nhận thanh toán💳",
        preheader="Hệ thống đã ghi nhận thanh toán và đang chờ admin duyệt.",
        username=username,
        message_html=body,
        button_text="Vào trang web",
        button_url=get_base_url(),
        note_html=None
    )

def build_admin_email(username, email, plan_code, months, approve_url):
    user = User.query.filter_by(username=username).first()
    checkout = calc_plan_checkout_for_user(user, plan_code, months)

    raw_total = checkout["raw_total"]
    discount = checkout["discount"]
    final_total = checkout["final_total"]
    plan_name = checkout["plan"].name
    rate = 0
    if raw_total > 0:
        rate = discount / raw_total
    memo = f"{username} - {norm_plan(plan_code)} - {months}m"

    body = f"""
      <p style="margin:0 0 10px;"><strong>Xin chào, Admin!</strong></p>

      <p style="margin:0 0 12px;">
        Hệ thống nhận được yêu cầu gia hạn từ user sau:
      </p>

      <div style="
        margin:14px 0 14px;
        padding:14px 16px;
        background:#f9fafb;
        border:1px solid #e5e7eb;
        border-radius:12px;
        line-height:1.8;
      ">
        <div><strong>User:</strong> {username}</div>
        <div><strong>Email:</strong> {email}</div>
        <div><strong>Gói:</strong> {plan_name} ({norm_plan(plan_code)})</div>
        <div><strong>Số tháng:</strong> {months}</div>
        <div><strong>Số tiền:</strong> {fmt_vnd(raw_total)}</div>
        <div><strong>Giảm giá:</strong> -{fmt_vnd(discount)} ({int(rate*100)}%)</div>
        <div><strong>Thành tiền:</strong> {fmt_vnd(final_total)}</div>
        <div><strong>Ghi chú:</strong> <code>{memo}</code></div>
      </div>
    """

    return render_app_email(
        subject_title="🗳️Yêu cầu duyệt gia hạn🗳️",
        preheader="Có một user vừa xác nhận đã thanh toán và đang chờ admin duyệt.",
        username="Admin",
        message_html=body,
        button_text="Xác nhận User",
        button_url=approve_url,
        note_html=None
    )

def build_user_approved_email(username, plan_code, months, trial_start, trial_end):
    plan_name = plan_display(plan_code)

    start_str = trial_start.strftime("%d/%m/%Y %H:%M")
    end_str = trial_end.strftime("%d/%m/%Y %H:%M")

    body = f"""
      <p style="margin:0 0 10px;"><strong>Xin chào, {username}!</strong></p>

      <p style="margin:0 0 12px;">
        Thanh toán của bạn đã được admin duyệt thành công.
      </p>

      <div style="
        margin:14px 0 14px;
        padding:14px 16px;
        background:#f9fafb;
        border:1px solid #e5e7eb;
        border-radius:12px;
        line-height:1.8;
      ">
        <div><strong>Gói đã duyệt:</strong> {plan_name} (<strong>{norm_plan(plan_code)}</strong>)</div>
        <div><strong>Số tháng:</strong> {months}</div>
        <div><strong>Bắt đầu tính từ:</strong> {start_str}</div>
        <div><strong>Hạn sử dụng đến:</strong> {end_str}</div>
      </div>

      <p style="margin:0 0 8px;">
        Bạn có thể vào hệ thống học tập để tiếp tục sử dụng.
      </p>

      <p style="margin:10px 0 0;">
        Chúc bạn có những buổi học và ôn tập thật thú vị.
      </p>

      <p style="margin:10px 0 0;"><strong>Xin cảm ơn!</strong></p>
    """

    return render_app_email(
        subject_title="✔️Thanh toán đã được duyệt✔️",
        preheader="Tài khoản của bạn đã được admin duyệt thành công.",
        username=username,
        message_html=body,
        button_text="Vào hệ thống học tập",
        button_url=get_base_url(),
        note_html=None
    )



def get_signer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="renew-approve")

@app.post("/renew/confirm_paid")
def renew_confirm_paid():
    try:
        data = request.get_json(silent=True) or request.form or {}

        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()

        user = None
        if username:
            user = User.query.filter_by(username=username).first()
        if not user and email:
            user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"ok": False, "message": "Không tìm thấy user để xác nhận thanh toán."}), 400

        plan_code = norm_plan(data.get("plan_code"))
        if plan_code == "FREE":
            return jsonify({"ok": False, "message": "Gói đăng ký không hợp lệ."}), 400

        try:
            months = int(data.get("months", 1))
        except Exception:
            months = 1

        if months <= 0:
            months = 1

        promo_code = (data.get("promo_code") or "").strip().upper()
        memo = (data.get("note") or f"{user.username} - {plan_code} - {months}m").strip()

        checkout = calc_plan_checkout_for_user(user, plan_code, months)

        raw_total = int(checkout["raw_total"] or 0)
        discount = int(checkout["discount"] or 0)
        final_total = int(checkout["final_total"] or 0)
        plan_name = checkout["plan"].name if checkout.get("plan") else plan_display(plan_code)

        promo_discount = 0

        if promo_code:
            promo, promo_msg = get_promotion_by_code_for_user(user, promo_code, plan_code)
            if not promo:
                return jsonify({"ok": False, "message": promo_msg}), 400

            after_month_discount = raw_total - discount

            if str(promo.discount_type or "").lower() == "percent":
                promo_discount = int(after_month_discount * float(promo.discount_value or 0) / 100)
            else:
                promo_discount = int(promo.discount_value or 0)

            final_total = max(after_month_discount - promo_discount, 0)
            discount = discount + promo_discount

        token = get_signer().dumps({
            "uid": user.id,
            "plan_code": plan_code,
            "months": months,
            "ts": datetime.now(timezone.utc).timestamp()
        })

        old_plan_code = norm_plan(user.member or "FREE")
        pending_change_type = get_pending_change_type(user, plan_code)

        # pending info
        user.pending_plan_code = plan_code
        user.pending_member = old_plan_code
        user.pending_member_name = plan_name
        user.pending_months = months
        user.pending_amount = raw_total
        user.pending_discount = discount
        user.pending_final_total = final_total
        user.pending_duration_label = f"{months} tháng"
        user.pending_memo = memo
        user.pending_at = datetime.now(timezone.utc).isoformat()
        user.pending_approve_token = token

        # Hết hạn rồi mới mua => WAIT_ACCEPT
        # Còn hạn mà mua thêm / đổi gói => vẫn ACTIVE để tiếp tục học
        if pending_change_type == "expired_renew":
            user.status = "WAIT_ACCEPT"
        else:
            user.status = "ACTIVE"

        db.session.commit()

        try:
            create_notification(
                role="admin",
                title=f"User {user.username} vừa gửi yêu cầu gia hạn",
                message=(
                    f"User: {user.username}\n"
                    f"Email: {user.email or ''}\n"
                    f"Gói: {plan_name} ({plan_code})\n"
                    f"Số tháng: {months}\n"
                    f"Thành tiền: {fmt_vnd(final_total)}\n"
                    f"Ghi chú: {memo}\n"
                    f"Trạng thái: Chờ admin duyệt"
                ),
                target_url=url_for("admin_users"),
                icon="💳",
                action_type="renew_request",
                ref_user_id=user.id,
                ref_plan_code=plan_code,
                ref_months=months
            )
        except Exception as e:
            print("[create_notification] ERROR:", e)

        # Telegram cho admin
        try:
            send_telegram_renew_request(user, {
                "plan_code": plan_code,
                "plan_name": plan_name,
                "months": months,
                "amount": final_total,
                "memo": memo
            })
        except Exception as e:
            print("[renew_confirm_paid] send telegram failed:", e)

        # lưu session để popup hiện lại ở login
        session["wait_accept_username"] = user.username
        session["wait_accept_email"] = user.email or ""

        approve_url = request.host_url.rstrip("/") + url_for("renew_approve", token=token)

        user_mail_ok = False
        admin_mail_ok = False

        # mail cho user
        if user.email:
            try:
                html_user = build_user_waitaccept_email(user.username, plan_code, months)
                user_mail_ok = send_email(
                    user.email,
                    "Đã xác nhận thanh toán - Chờ admin duyệt",
                    html_user
                )
                print("[renew_confirm_paid] user_mail_ok =", user_mail_ok, "->", user.email)
            except Exception as e:
                print("[renew_confirm_paid] send user email failed:", e)

        # mail cho admin
        try:
            html_admin = build_admin_email(
                username=user.username,
                email=user.email or "",
                plan_code=plan_code,
                months=months,
                approve_url=approve_url
            )
            admin_mail_ok = send_email(
                ADMIN_EMAIL,
                "Yêu cầu duyệt gia hạn",
                html_admin
            )
            print("[renew_confirm_paid] admin_mail_ok =", admin_mail_ok, "->", ADMIN_EMAIL)
        except Exception as e:
            print("[renew_confirm_paid] send admin email failed:", e)

        return jsonify({
            "ok": True,
            "user_mail_ok": user_mail_ok,
            "admin_mail_ok": admin_mail_ok
        })

    except Exception as e:
        db.session.rollback()
        print("[renew_confirm_paid] ERROR:", e)
        return jsonify({"ok": False, "message": str(e)}), 500



@app.route("/telegram/webhook", methods=["POST"], strict_slashes=False)
def telegram_webhook():
    try:
        print("✅ TELEGRAM WEBHOOK HIT")
        print(request.get_json(silent=True))

        update = request.get_json(silent=True) or {}
        cb = update.get("callback_query")
        if not cb:
            return "ok"

        data = cb.get("data", "") or ""
        parts = data.split(":")
        action = parts[0] if parts else ""

        if action not in ("APPROVE", "REJECT"):
            return "ok"

        if len(parts) < 2:
            return "ok"

        try:
            user_id = int(parts[1])
        except Exception:
            return "ok"

        user = User.query.get(user_id)
        if not user:
            return "ok"

        if action == "REJECT":
            user.status = "ACTIVE" if user.trial_end and user.trial_end > now_utc() else "pending"
            user.pending_approve_token = None
            user.pending_plan_code = None
            user.pending_member = None
            user.pending_member_name = None
            user.pending_months = None
            user.pending_amount = None
            user.pending_discount = None
            user.pending_final_total = None
            user.pending_duration_label = None
            user.pending_memo = None
            user.pending_at = None
            db.session.commit()
            return "ok"

        # APPROVE
        # Hỗ trợ cả format mới: APPROVE:user_id:months:sign
        # và format cũ: APPROVE:user_id
        months = int(user.pending_months or 1)

        if len(parts) >= 4:
            try:
                cb_months = int(parts[2])
            except Exception:
                cb_months = months

            sign = parts[3]
            if sign != sign_payload(f"{user_id}:{cb_months}"):
                return "invalid"

            months = cb_months

        plan_code = norm_plan(user.pending_plan_code or user.member or "FREE")
        apply_approved_membership(user, plan_code, months)

        # clear pending
        user.pending_approve_token = None
        user.pending_plan_code = None
        user.pending_member = None
        user.pending_member_name = None
        user.pending_months = None
        user.pending_amount = None
        user.pending_discount = None
        user.pending_final_total = None
        user.pending_duration_label = None
        user.pending_memo = None
        user.pending_at = None

        db.session.commit()

        try:
            if user.email:
                html_ok = build_user_approved_email(
                    username=user.username,
                    plan_code=plan_code,
                    months=months,
                    trial_start=user.trial_start,
                    trial_end=user.trial_end
                )
                send_email(user.email, "Thanh toán đã được duyệt - Taekwondo", html_ok)
        except Exception as e:
            print("[telegram_webhook] send approved mail failed:", e)

        return "ok"

    except Exception as e:
        db.session.rollback()
        print("[telegram_webhook] ERROR:", e)
        return "ok"

@app.route("/ping")
def ping():
    return "pong"


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_PATH)

EMAIL_SENDER = (os.getenv("EMAIL_SENDER") or "").strip()
EMAIL_APP_PASSWORD = (os.getenv("EMAIL_APP_PASSWORD") or "").strip()

# admin nhận mail duyệt (Ken đang muốn cố định)
ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL") or "silentnight1993pro@gmail.com").strip()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_ADMIN_CHAT_ID = os.getenv("TELEGRAM_ADMIN_CHAT_ID", "")
TELEGRAM_SECRET = os.getenv("TELEGRAM_SECRET", "CHANGE_ME")
def send_telegram_renew_request(user, payload):
    """
    Gửi tin nhắn Telegram cho admin + nút duyệt/từ chối.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_ADMIN_CHAT_ID:
        print("[TELEGRAM] Missing TELEGRAM_BOT_TOKEN / TELEGRAM_ADMIN_CHAT_ID")
        return

    months = int(payload.get("months", 1) or 1)
    sign = sign_payload(f"{user.id}:{months}")

    text = (
        "🧾 <b>YÊU CẦU GIA HẠN</b>\n"
        f"👤 User: <code>{user.username}</code>\n"
        f"📧 Email: <code>{user.email or ''}</code>\n"
        f"🎯 Gói: <b>{payload.get('plan_name','') or payload.get('member_name','')}</b> "
        f"({payload.get('plan_code','') or payload.get('member','')})\n"
        f"🗓️ Số tháng: <b>{months}</b>\n"
        f"💰 Số tiền: <b>{payload.get('amount',0):,} VNĐ</b>\n"
        f"📝 Ghi chú: <code>{payload.get('memo','')}</code>\n\n"
        "Bấm nút bên dưới để duyệt."
    )

    keyboard = {
        "inline_keyboard": [
            [
                {"text": "✅ DUYỆT", "callback_data": f"APPROVE:{user.id}:{months}:{sign}"},
                {"text": "❌ TỪ CHỐI", "callback_data": f"REJECT:{user.id}"}
            ]
        ]
    }

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    requests.post(
        url,
        json={
            "chat_id": TELEGRAM_ADMIN_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": keyboard
        },
        timeout=10
    )




def tg_api(method: str):
    return f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"

def tg_send(text: str, reply_markup=None):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_ADMIN_CHAT_ID:
        print("Telegram chưa cấu hình")
        return

    payload = {
        "chat_id": TELEGRAM_ADMIN_CHAT_ID,
        "text": text,
        "parse_mode": "HTML"
    }

    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)

    requests.post(tg_api("sendMessage"), data=payload, timeout=10)

def sign_payload(data: str) -> str:
    return hmac.new(
        TELEGRAM_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()[:12]





def has_accessible_folder3_under_folder2(folder2_id):
    folder3_list = (
        Folder.query
        .filter_by(level=3, parent_id=folder2_id)
        .order_by(Folder.order_index)
        .all()
    )
    return any(can_access_plans(f3.member_plans) for f3 in folder3_list)


def has_accessible_folder3_under_folder1(folder1_id):
    folder2_list = (
        Folder.query
        .filter_by(level=2, parent_id=folder1_id)
        .order_by(Folder.order_index)
        .all()
    )
    return any(has_accessible_folder3_under_folder2(f2.id) for f2 in folder2_list)


@app.route("/Page")
@login_required
def page_root():
    # ===============================
    # HỌC TAEKWONDO – EDU LEVEL 1
    # ===============================
    edu_folders = (
        EduFolder.query
        .filter(
            EduFolder.level == 1,
            EduFolder.is_active == 1
        )
        .order_by(EduFolder.order.asc(), EduFolder.id.asc())
        .all()
    )

    # ===============================
    # ÔN TẬP – FOLDER CẤP 1
    # Chỉ hiện nếu bên dưới còn ít nhất 1 folder3 user được quyền thấy
    # ===============================
    all_folder1 = (
        Folder.query
        .filter_by(level=1)
        .order_by(Folder.order_index)
        .all()
    )

    folder1_list = [
        f1 for f1 in all_folder1
        if has_accessible_folder3_under_folder1(f1.id)
    ]

    items = [{
        "name": f.name,
        "image": url_for("static", filename=f.image) if f.image else None,
        "url": url_for("page_level1", slug1=slugify(f.name))
    } for f in folder1_list]

    return render_template(
        "folder_list.html",
        page_title="Trang chủ",
        edu_folders=edu_folders,
        lessons=[],
        items=items,
        breadcrumbs=[{"name": "Trang chủ", "url": None}],
        mode="home"
    )






@app.route("/Page/<slug1>")
@login_required
def page_level1(slug1):
    f1 = next(
        (f for f in Folder.query.filter_by(level=1).order_by(Folder.order_index).all()
         if slugify(f.name) == slug1),
        None
    )
    if not f1:
        abort(404)

    # Nếu folder1 này không còn nội dung nào user được phép thấy -> 404
    if not has_accessible_folder3_under_folder1(f1.id):
        abort(404)

    all_folder2 = (
        Folder.query
        .filter_by(level=2, parent_id=f1.id)
        .order_by(Folder.order_index)
        .all()
    )

    folder2_list = [
        f2 for f2 in all_folder2
        if has_accessible_folder3_under_folder2(f2.id)
    ]

    items = [{
        "name": f.name,
        "image": url_for("static", filename=f.image) if f.image else None,
        "url": url_for("page_level2", slug1=slug1, slug2=slugify(f.name))
    } for f in folder2_list]

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("page_root")},
        {"name": "Ôn Tập", "url": url_for("page_root")},
        {"name": f1.name, "url": None}
    ]

    return render_template(
        "folder_list.html",
        page_title=f1.name,
        items=items,
        breadcrumbs=breadcrumbs,
        mode="practice",
        edu_folders=[],
        lessons=[]
    )


@app.route("/Page/<slug1>/<slug2>")
@login_required
def page_level2(slug1, slug2):
    f1 = next(
        (f for f in Folder.query.filter_by(level=1).order_by(Folder.order_index).all()
         if slugify(f.name) == slug1),
        None
    )
    if not f1:
        abort(404)

    f2 = next(
        (f for f in Folder.query.filter_by(level=2, parent_id=f1.id).order_by(Folder.order_index).all()
         if slugify(f.name) == slug2),
        None
    )
    if not f2:
        abort(404)

    # Nếu folder2 này không còn folder3 nào user được phép thấy -> 404
    if not has_accessible_folder3_under_folder2(f2.id):
        abort(404)

    all_folder3 = (
        Folder.query
        .filter_by(level=3, parent_id=f2.id)
        .order_by(Folder.order_index)
        .all()
    )

    folder3_list = [
        f3 for f3 in all_folder3
        if can_access_plans(f3.member_plans)
    ]

    items = [{
        "name": f.name,
        "image": url_for("static", filename=f.image) if f.image else None,
        "url": url_for("quiz_prepare", folder3_id=f.id)
    } for f in folder3_list]

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("page_root")},
        {"name": "Ôn Tập", "url": url_for("page_root")},
        {"name": f1.name, "url": url_for("page_level1", slug1=slugify(f1.name))},
        {"name": f2.name, "url": None}
    ]

    return render_template(
        "folder_list.html",
        page_title=f2.name,
        items=items,
        breadcrumbs=breadcrumbs,
        mode="practice",
        edu_folders=[],
        lessons=[]
    )


@app.before_request
def force_change_password():
    if not current_user.is_authenticated:
        return

    # các route cho phép khi chưa đổi mật khẩu
    allowed = [
        "account",
        "account_change_password",
        "logout",
        "static"
    ]

    if current_user.must_change_password:
        if request.endpoint not in allowed:
            return redirect(url_for("account"))


ALLOWED_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "yahoo.com.vn",
    "outlook.com",
    "hotmail.com",
    "icloud.com"
]
def is_valid_email(email):
    if "@" not in email:
        return False
    domain = email.split("@")[-1].lower()
    return domain in ALLOWED_EMAIL_DOMAINS


def ensure_user_pref_columns():
    """
    ✅ SQLite migration nhẹ: thêm các cột còn thiếu trong table user
    (không xoá dữ liệu).
    """
    try:
        rows = db.session.execute(db.text("PRAGMA table_info(user)")).fetchall()
        existing = {r[1] for r in rows}  # name is index 1

        def add(col_name: str, col_def_sql: str):
            if col_name in existing:
                return
            db.session.execute(db.text(f"ALTER TABLE user ADD COLUMN {col_name} {col_def_sql}"))

        # ===== các cột cũ khác (nếu thiếu) =====
        add("nickname", "TEXT")
        add("must_change_password", "INTEGER DEFAULT 0")
        add("pref_num_questions", "INTEGER DEFAULT 15")
        add("pref_time_per_q", "INTEGER DEFAULT 20")

        # ===== email verify =====
        add("email_verified", "INTEGER DEFAULT 0")
        add("email_verified_at", "TEXT")
        add("activation_token", "TEXT")
        add("activation_sent_at", "TEXT")

        # ===== pending renew / membership =====
        add("pending_plan_code", "TEXT")
        add("pending_months", "INTEGER")
        add("pending_amount", "INTEGER")
        add("pending_discount", "INTEGER")
        add("pending_final_total", "INTEGER")
        add("pending_member", "TEXT")
        add("pending_member_name", "TEXT")
        add("pending_duration_label", "TEXT")
        add("pending_memo", "TEXT")
        add("pending_at", "TEXT")
        add("pending_approve_token", "TEXT")

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        print("[ensure_user_pref_columns] ERROR:", e)




@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        nickname = (request.form.get("nickname") or "").strip()

        if not nickname:
            flash("❌ Tên hiển thị không được trống.", "danger")
            return redirect(url_for("account"))

        # giới hạn cho đẹp (tuỳ Ken)
        if len(nickname) > 30:
            flash("❌ Tên hiển thị tối đa 30 ký tự.", "danger")
            return redirect(url_for("account"))

        current_user.nickname = nickname
        db.session.commit()
        flash("✅ Đã lưu tên hiển thị!", "success")
        return redirect(url_for("main"))

    return render_template("account.html", force_pw=current_user.must_change_password)


@app.route("/account/change-password", methods=["POST"])
@login_required
def account_change_password():
    cur = request.form.get("current_password", "")
    newp = request.form.get("new_password", "")
    rep = request.form.get("re_password", "")

    # 1️⃣ kiểm tra mật khẩu hiện tại
    if not check_password_hash(current_user.pw_hash, cur):
        flash("❌ Mật khẩu hiện tại không đúng.", "danger_pw")
        return redirect(url_for("account"))

    # 2️⃣ kiểm tra nhập lại
    if newp != rep:
        flash("❌ Mật khẩu nhập lại không khớp.", "danger_pw")
        return redirect(url_for("account"))

    # 3️⃣ kiểm tra độ dài
    if len(newp) < 6:
        flash("❌ Mật khẩu mới phải tối thiểu 6 ký tự.", "danger_pw")
        return redirect(url_for("account"))

    # ===============================
    # 🔐 PHẦN KEN HỎI KIỂM TRA Ở ĐÂU
    # ===============================

    # 4️⃣ đổi mật khẩu + gỡ cờ bắt buộc
    current_user.pw_hash = generate_password_hash(newp)
    current_user.must_change_password = False   # ✅ C.1
    db.session.commit()

    # 5️⃣ báo thành công + cho vào hệ thống
    flash("✅ Đổi mật khẩu thành công!", "success_pw")
    return redirect(url_for("main"))             # ✅ C.2


def write_login_log_summary(username, ip, status):

    uname = (username or "").strip().lower()
    if not uname:
        uname = "unknown"

    st = (status or "").strip().lower()
    now_dt = datetime.utcnow()

    row = LoginLogSummary.query.filter_by(username=uname).first()

    if not row:
        row = LoginLogSummary(
            username=uname,
            last_ip=ip,
            last_at=now_dt,
            success_count=0,
            failed_count=0,
            blocked_count=0,
            locked_count=0,
            wait_accept_count=0,
            expired_count=0,
            wait_renew_count=0
        )
        db.session.add(row)

    row.last_ip = ip
    row.last_at = now_dt

    if st == "success":
        row.success_count += 1
    elif st == "failed":
        row.failed_count += 1
    elif st == "blocked":
        row.blocked_count += 1
    elif st == "locked":
        row.locked_count += 1
    elif st == "wait_accept":
        row.wait_accept_count += 1
    elif st == "expired":
        row.expired_count += 1
    elif st == "wait_renew":
        row.wait_renew_count += 1

def ensure_schema():
    """Core schema: question / folder / user (nền tảng)"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    def get_cols(table):
        cur.execute(f"PRAGMA table_info({table})")
        return [r[1] for r in cur.fetchall()]

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    # ===== QUESTION =====
    if "question" in tables:
        cols = get_cols("question")
        if "folder_id" not in cols:
            cur.execute("ALTER TABLE question ADD COLUMN folder_id INTEGER")
        if "topic_id" not in cols:
            cur.execute("ALTER TABLE question ADD COLUMN topic_id INTEGER")

    # ===== FOLDER =====
    if "folder" in tables:
        cols = get_cols("folder")
        if "image" not in cols:
            cur.execute("ALTER TABLE folder ADD COLUMN image VARCHAR(255)")

    # ===== USER – CORE =====
    if "user" in tables:
        cols = get_cols("user")

        if "last_score" not in cols:
            cur.execute("ALTER TABLE user ADD COLUMN last_score INTEGER")

        if "last_total" not in cols:
            cur.execute("ALTER TABLE user ADD COLUMN last_total INTEGER")

        if "play_count" not in cols:
            cur.execute(
                "ALTER TABLE user ADD COLUMN play_count INTEGER DEFAULT 0"
            )

    if "folder" in tables:
        cols = get_cols("folder")
        if "order_index" not in cols:
            cur.execute("ALTER TABLE folder ADD COLUMN order_index INTEGER")


    conn.commit()
    conn.close()

def ensure_lesson_pdf_column():
    """✅ Add lessons.pdf nếu DB cũ chưa có"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "lessons" in tables:
        cur.execute("PRAGMA table_info(lessons)")
        cols = [r[1] for r in cur.fetchall()]
        if "pdf" not in cols:
            cur.execute("ALTER TABLE lessons ADD COLUMN pdf VARCHAR(255) DEFAULT 'Bai_hoc.pdf'")

    conn.commit()
    conn.close()

def ensure_lesson_media_columns():
    """✅ Add lessons.review_type + lessons.source_url nếu DB cũ chưa có"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "lessons" in tables:
        cur.execute("PRAGMA table_info(lessons)")
        cols = [r[1] for r in cur.fetchall()]

        if "review_type" not in cols:
            cur.execute("ALTER TABLE lessons ADD COLUMN review_type VARCHAR(20) DEFAULT 'pdf'")

        if "source_url" not in cols:
            cur.execute("ALTER TABLE lessons ADD COLUMN source_url TEXT")

    conn.commit()
    conn.close()

def ensure_lesson_member_plans_column():
    """✅ Add lessons.member_plans nếu DB cũ chưa có"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "lessons" in tables:
        cur.execute("PRAGMA table_info(lessons)")
        cols = [r[1] for r in cur.fetchall()]

        if "member_plans" not in cols:
            cur.execute(
                "ALTER TABLE lessons ADD COLUMN member_plans VARCHAR(100) DEFAULT 'FREE,BASIC,PRO,VIP'"
            )

    conn.commit()
    conn.close()

def ensure_folder_member_plans_column():
    """✅ Add folder.member_plans nếu DB cũ chưa có"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "folder" in tables:
        cur.execute("PRAGMA table_info(folder)")
        cols = [r[1] for r in cur.fetchall()]

        if "member_plans" not in cols:
            cur.execute(
                "ALTER TABLE folder ADD COLUMN member_plans VARCHAR(100) DEFAULT 'FREE,BASIC,PRO,VIP'"
            )

    conn.commit()
    conn.close()

def ensure_question_member_plans_column():
    """✅ Add question.member_plans nếu DB cũ chưa có"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "question" in tables:
        cur.execute("PRAGMA table_info(question)")
        cols = [r[1] for r in cur.fetchall()]

        if "member_plans" not in cols:
            cur.execute(
                "ALTER TABLE question ADD COLUMN member_plans VARCHAR(100) DEFAULT 'FREE,BASIC,PRO,VIP'"
            )

    conn.commit()
    conn.close()

def ensure_lesson_media_columns():
    """✅ Add lessons.review_type + lessons.source_url nếu DB cũ chưa có"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "lessons" in tables:
        cur.execute("PRAGMA table_info(lessons)")
        cols = [r[1] for r in cur.fetchall()]

        if "review_type" not in cols:
            cur.execute("ALTER TABLE lessons ADD COLUMN review_type VARCHAR(20) DEFAULT 'pdf'")

        if "source_url" not in cols:
            cur.execute("ALTER TABLE lessons ADD COLUMN source_url TEXT")

    conn.commit()
    conn.close()

def ensure_promotion_code_column():
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "promotion_campaign" in tables:
        cur.execute("PRAGMA table_info(promotion_campaign)")
        cols = [r[1] for r in cur.fetchall()]
        if "code" not in cols:
            cur.execute("ALTER TABLE promotion_campaign ADD COLUMN code VARCHAR(50)")

    conn.commit()
    conn.close()

def ensure_promotion_kind_column():
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    tables = {r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "promotion_campaign" in tables:
        cur.execute("PRAGMA table_info(promotion_campaign)")
        cols = [r[1] for r in cur.fetchall()]
        if "promo_kind" not in cols:
            cur.execute(
                "ALTER TABLE promotion_campaign ADD COLUMN promo_kind VARCHAR(20) DEFAULT 'campaign'"
            )

    conn.commit()
    conn.close()

def now_utc():
    return datetime.now(timezone.utc)

class SafeDateTime(TypeDecorator):
    """
    SQLite đôi khi lưu datetime dạng text, có thể bị ''.
    Class này đọc '' => None để tránh ValueError: Invalid isoformat string: ''.
    """
    impl = SAString
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str) and value.strip() == "":
            return None
        if isinstance(value, datetime):
            # lưu dạng ISO (có space)
            return value.replace(microsecond=0).isoformat(sep=" ")
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str) and value.strip() == "":
            return None
        if isinstance(value, datetime):
            return value
        try:
            s = str(value).strip().replace("Z", "+00:00")
            return datetime.fromisoformat(s)
        except Exception:
            return None


# ===================== MODELS =====================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    pw_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), default="user")
    is_deleted = db.Column(db.Boolean, default=False)

    email = db.Column(db.String(120))
    nickname = db.Column(db.String(120))
    must_change_password = db.Column(db.Boolean, default=False)
    pref_num_questions = db.Column(db.Integer)
    pref_time_per_q = db.Column(db.Integer)

    last_score = db.Column(db.Integer)
    last_total = db.Column(db.Integer)

    # Ken đang dùng member làm gói => giữ nguyên
    member = db.Column(db.String(20), default="Free")
    play_count = db.Column(db.Integer, default=0)

    # ✅ dùng SafeDateTime để không chết vì '' trong DB
    created_at = db.Column(SafeDateTime, default=lambda: now_utc().isoformat())
    trial_start = db.Column(SafeDateTime, nullable=True)
    trial_end = db.Column(SafeDateTime, nullable=True)

    status = db.Column(db.String(20), default="pending")
    email_verified = db.Column(db.Boolean, default=False)
    email_verified_at = db.Column(SafeDateTime, nullable=True)

    activation_token = db.Column(db.String(255), nullable=True)
    activation_sent_at = db.Column(SafeDateTime, nullable=True)

    # ✅ các cột pending_ đã có trong quiz.db => khai báo để khỏi AttributeError
    # ✅ các cột pending_
    pending_member = db.Column(db.Text, nullable=True)
    pending_member_name = db.Column(db.Text, nullable=True)
    pending_plan_code = db.Column(db.Text, nullable=True)
    pending_months = db.Column(db.Integer, nullable=True)
    pending_amount = db.Column(db.Integer, nullable=True)
    pending_discount = db.Column(db.Integer, nullable=True)
    pending_final_total = db.Column(db.Integer, nullable=True)
    pending_duration_label = db.Column(db.Text, nullable=True)
    pending_memo = db.Column(db.Text, nullable=True)
    pending_at = db.Column(db.Text, nullable=True)
    pending_approve_token = db.Column(db.Text, nullable=True)


class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip = db.Column(db.String(50))
    status = db.Column(db.String(30))  # success / blocked / failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLogSummary(db.Model):
    __tablename__ = "login_log_summary"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True, index=True)

    last_ip = db.Column(db.String(50))
    last_at = db.Column(db.DateTime, default=datetime.utcnow)

    success_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    blocked_count = db.Column(db.Integer, default=0)
    locked_count = db.Column(db.Integer, default=0)
    wait_accept_count = db.Column(db.Integer, default=0)
    expired_count = db.Column(db.Integer, default=0)
    wait_renew_count = db.Column(db.Integer, default=0)


# ===================== ACCESS CONTROL =====================

class AccessSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.String(20), nullable=False, default="all")
    # mode: admin_only | all | custom


class AccessAllow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    user = db.relationship("User")



class Set(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    set_id = db.Column(db.Integer, db.ForeignKey("set.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)

    set = db.relationship("Set", backref=db.backref("topics", lazy=True))

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Tạm giữ để code cũ không vỡ, chưa dùng nữa
    topic_id = db.Column(db.Integer, db.ForeignKey("topic.id"), nullable=True)
    topic = db.relationship("Topic")

    folder_id = db.Column(db.Integer, db.ForeignKey("folder.id"), nullable=True)
    folder = db.relationship("Folder")

    type = db.Column(db.String(20), default="mcq")   # mcq / boolean / multi
    text = db.Column(db.Text, nullable=False)
    member_plans = db.Column(db.String(100), default="FREE,BASIC,PRO,VIP")

    # ===== NEW: đáp án gộp vào question =====
    answer_1 = db.Column(db.Text)
    answer_2 = db.Column(db.Text)
    answer_3 = db.Column(db.Text)
    answer_4 = db.Column(db.Text)
    answer_5 = db.Column(db.Text)
    answer_6 = db.Column(db.Text)
    answer_7 = db.Column(db.Text)
    answer_8 = db.Column(db.Text)
    answer_9 = db.Column(db.Text)
    answer_10 = db.Column(db.Text)
    answer_11 = db.Column(db.Text)
    answer_12 = db.Column(db.Text)

    answer_count = db.Column(db.Integer, default=0)
    correct_indexes = db.Column(db.Text)         # ví dụ: "3" hoặc "2,3,4"
    correct_answers_text = db.Column(db.Text)    # ví dụ: "đá vòng" hoặc "đá ngang||đá vòng||đá lái"

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)

    level = db.Column(db.Integer, nullable=False, default=1)

    parent_id = db.Column(db.Integer, db.ForeignKey("folder.id"), nullable=True)
    parent = db.relationship(
        "Folder",
        remote_side=[id],
        backref=db.backref("children", lazy=True)
    )
    member_plans = db.Column(db.String(100), default="FREE,BASIC,PRO,VIP")
    order_index = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(255))

    is_active_practice = db.Column(db.Integer, default=1)  # ✅ BẬT / TẮT

    


class Choice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, default=False)

    question = db.relationship(
        "Question",
        backref=db.backref("choices", lazy=True, cascade="all, delete-orphan")
    )


class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey("topic.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)

    # ✅ NEW
    question_count = db.Column(db.Integer, default=10)   # 10/20/30/60
    time_per_q = db.Column(db.Integer, nullable=True)     # giây

    user = db.relationship("User", backref=db.backref("attempts", lazy=True))
    topic = db.relationship("Topic", backref=db.backref("attempts", lazy=True))

class AttemptAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey("attempt.id"))
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"))

    # ⬇️ GIỮ cho MCQ / TRUE-FALSE
    chosen_choice_id = db.Column(db.Integer, nullable=True)

    # 🔥 THÊM DÒNG NÀY CHO MULTI
    chosen_choice_ids = db.Column(db.Text, nullable=True)  # JSON string
    is_correct = db.Column(db.Boolean, default=False)

    # ✅ NEW: đánh dấu đã xử lý câu hỏi hay chưa
    answered = db.Column(db.Boolean, default=False)

    attempt = db.relationship("Attempt", backref=db.backref("answers", lazy=True))
    question = db.relationship("Question")

def question_answer_texts(q):
    return [
        q.answer_1, q.answer_2, q.answer_3, q.answer_4,
        q.answer_5, q.answer_6, q.answer_7, q.answer_8,
        q.answer_9, q.answer_10, q.answer_11, q.answer_12
    ]


def question_answers_payload(q, shuffle_answers=False, forced_order=None):
    """
    Trả về danh sách đáp án dạng:
    [
      {"orig_idx": 1, "label": "A", "text": "..."},
      {"orig_idx": 2, "label": "B", "text": "..."},
      ...
    ]

    - orig_idx = vị trí gốc trong question.answer_1 ... answer_12
    - label = A/B/C/D... chỉ để hiển thị
    - forced_order = danh sách thứ tự cố định, ví dụ [3,1,4,2]
    """
    answers_map = {}

    for idx, txt in enumerate(question_answer_texts(q), start=1):
        txt = (txt or "").strip()
        if txt:
            answers_map[idx] = {
                "orig_idx": idx,
                "text": txt
            }

    # ===== nếu có thứ tự cố định thì ưu tiên dùng =====
    if forced_order:
        ordered = []
        for idx in forced_order:
            if idx in answers_map:
                ordered.append(answers_map[idx])
        answers = ordered
    else:
        answers = list(answers_map.values())
        if shuffle_answers:
            random.shuffle(answers)

    for pos, item in enumerate(answers):
        item["label"] = chr(65 + pos)  # A B C D ...
    return answers


def parse_correct_indexes(q):
    raw = (q.correct_indexes or "").strip()
    if not raw:
        return set()

    out = set()
    for x in raw.split(","):
        x = x.strip()
        if x.isdigit():
            out.add(int(x))
    return out


def fill_question_answers(q, answers, correct_indexes):
    """
    answers: list[str]
    correct_indexes: list[int] hoặc set[int] (theo thứ tự answer_1..answer_12)
    """
    clean_answers = [(a or "").strip() for a in answers if (a or "").strip()]
    clean_answers = clean_answers[:12]

    # reset hết 12 cột
    for i in range(1, 13):
        setattr(q, f"answer_{i}", None)

    for i, txt in enumerate(clean_answers, start=1):
        setattr(q, f"answer_{i}", txt)

    q.answer_count = len(clean_answers)

    correct_indexes = sorted(
        i for i in set(int(x) for x in correct_indexes if str(x).strip().isdigit())
        if 1 <= i <= len(clean_answers)
    )

    q.correct_indexes = ",".join(str(i) for i in correct_indexes)
    q.correct_answers_text = "||".join(
        clean_answers[i - 1] for i in correct_indexes if 1 <= i <= len(clean_answers)
    )

# ===================== AUTH =====================
@app.context_processor
def inject_year():
    return {"current_year": datetime.now().year}

@app.context_processor
def inject_header_notifications():
    items = []
    unread_count = 0

    try:
        if current_user.is_authenticated:
            cleanup_old_notifications(30)

            if current_user.role == "admin":
                all_admin_items = (
                    Notification.query
                    .filter_by(role="admin")
                    .order_by(Notification.created_at.desc(), Notification.id.desc())
                    .all()
                )

                sorted_items = sorted(all_admin_items, key=admin_notification_priority)
                items = sorted_items[:10]
                unread_count = sum(1 for x in all_admin_items if not x.is_read)

            else:
                qs = (
                    Notification.query
                    .filter_by(role="user", user_id=current_user.id)
                    .order_by(Notification.created_at.desc(), Notification.id.desc())
                )
                unread_count = qs.filter_by(is_read=False).count()
                items = qs.limit(10).all()

    except Exception as e:
        print("[inject_header_notifications] ERROR:", e)

    return dict(
        header_notifications=items,
        header_notification_unread=unread_count
    )

@app.context_processor
def inject_member_plan_cards():
    try:
        if current_user.is_authenticated:
            return {
                "member_plan_cards": build_member_plan_cards_for_user(current_user),
                "payment_bank_setting": get_active_bank_setting(),
            }
    except Exception as e:
        print("[inject_member_plan_cards] ERROR:", e)

    return {
        "member_plan_cards": [],
        "payment_bank_setting": get_active_bank_setting(),
    }


def admin_notification_priority(n):
    action = (n.action_type or "").strip().lower()

    # 1. Gia hạn chưa duyệt
    if action == "renew_request" and not bool(n.is_done):
        return (0, -(n.id or 0))

    # 2. Feedback chưa đọc + chưa xử lý
    if action == "feedback" and not bool(n.is_read) and not bool(n.is_done):
        return (1, -(n.id or 0))

    # 3. Gia hạn đã duyệt
    if action == "renew_request" and bool(n.is_done):
        return (2, -(n.id or 0))

    # 4. Feedback đã đọc / đã trả lời
    if action == "feedback":
        return (3, -(n.id or 0))

    return (9, -(n.id or 0))

@app.route("/notifications/go/<int:noti_id>")
@login_required
def notification_go(noti_id):
    n = Notification.query.get_or_404(noti_id)

    if current_user.role == "admin":
        if n.role != "admin":
            abort(403)
    else:
        if n.role != "user" or n.user_id != current_user.id:
            abort(403)

    if not n.is_read:
        n.is_read = True
        db.session.commit()

    return redirect(url_for("notifications_page", id=n.id))


@app.route("/notifications/confirm/<int:noti_id>")
@login_required
def notification_confirm(noti_id):
    if current_user.role != "admin":
        abort(403)

    n = Notification.query.get_or_404(noti_id)

    if n.role != "admin":
        abort(403)

    if n.is_done:
        flash("Thông báo này đã được xác nhận trước đó.", "warning")
        return redirect(url_for("notifications_page", id=n.id))

    if n.action_type != "renew_request":
        flash("Thông báo này không hỗ trợ xác nhận.", "danger")
        return redirect(url_for("notifications_page", id=n.id))

    user = User.query.get(n.ref_user_id) if n.ref_user_id else None
    if not user or not n.ref_plan_code or not n.ref_months:
        flash("Thiếu dữ liệu để xác nhận gia hạn.", "danger")
        return redirect(url_for("notifications_page", id=n.id))

    plan_code = norm_plan(n.ref_plan_code)
    months = int(n.ref_months or 1)

    apply_approved_membership(user, plan_code, months)

    # clear pending
    user.pending_approve_token = None
    user.pending_plan_code = None
    user.pending_member = None
    user.pending_member_name = None
    user.pending_months = None
    user.pending_amount = None
    user.pending_discount = None
    user.pending_final_total = None
    user.pending_duration_label = None
    user.pending_memo = None
    user.pending_at = None

    n.is_done = True
    n.is_read = True
    n.title = f"Đã duyệt: {n.title}"

    db.session.commit()

    # ===== GỬI MAIL XÁC NHẬN CHO USER =====
    try:
        if user.email:
            html_ok = build_user_approved_email(
                username=user.username,
                plan_code=plan_code,
                months=months,
                trial_start=user.trial_start,
                trial_end=user.trial_end
            )
            send_email(
                user.email,
                "Thanh toán đã được duyệt - Taekwondo",
                html_ok
            )
            print("[notification_confirm] approve email sent to:", user.email)
    except Exception as e:
        print("[notification_confirm] send_mail failed:", e)

    flash(f"Đã xác nhận gia hạn cho user {user.username}.", "success")
    return redirect(url_for("notifications_page", id=n.id))

@app.route("/notifications/feedback", methods=["POST"])
@login_required
def notification_feedback():
    if current_user.role != "user":
        abort(403)

    title = (request.form.get("feedback_title") or "").strip()
    message = (request.form.get("feedback_message") or "").strip()

    if not title:
        flash("Vui lòng nhập tiêu đề feedback.", "danger")
        return redirect(url_for("notifications_page"))

    if not message:
        flash("Vui lòng nhập nội dung feedback.", "danger")
        return redirect(url_for("notifications_page"))

    n = Notification(
        role="admin",
        user_id=None,
        title=f"Feedback từ {current_user.username}: {title} 💬",
        message=(
            f"User: {current_user.username}\n"
            f"Email: {current_user.email or '-'}\n\n"
            f"{message}"
        ),
        target_url=url_for("notifications_page"),
        icon="💬",
        is_read=False,
        action_type="feedback",
        ref_user_id=current_user.id,
        is_done=False,
        created_at=now_vn()
    )
    db.session.add(n)
    db.session.commit()

    flash("Đã gửi feedback cho admin.", "success")
    return redirect(url_for("notifications_page"))

@app.route("/notifications/reply/<int:noti_id>", methods=["POST"])
@login_required
def notification_reply(noti_id):
    if current_user.role != "admin":
        abort(403)

    n = Notification.query.get_or_404(noti_id)

    if n.role != "admin":
        abort(403)

    if (n.action_type or "").strip().lower() != "feedback":
        flash("Thông báo này không phải feedback để trả lời.", "danger")
        return redirect(url_for("notifications_page", id=n.id))

    if n.is_done:
        flash("Feedback này đã được trả lời rồi.", "warning")
        return redirect(url_for("notifications_page", id=n.id))

    reply_title = (request.form.get("reply_title") or "").strip()
    reply_message = (request.form.get("reply_message") or "").strip()

    if not reply_title:
        flash("Vui lòng nhập tiêu đề trả lời.", "danger")
        return redirect(url_for("notifications_page", id=n.id))

    if not reply_message:
        flash("Vui lòng nhập nội dung trả lời.", "danger")
        return redirect(url_for("notifications_page", id=n.id))

    target_user = User.query.get(n.ref_user_id) if n.ref_user_id else None
    if not target_user:
        flash("Không tìm thấy user để trả lời feedback.", "danger")
        return redirect(url_for("notifications_page", id=n.id))

    # Tạo thông báo trả lời cho user
    reply_noti = Notification(
        role="user",
        user_id=target_user.id,
        title=f"Admin trả lời: {reply_title} 💬",
        message=reply_message,
        target_url=url_for("notifications_page"),
        icon="💬",
        is_read=False,
        action_type="feedback_reply",
        ref_user_id=target_user.id,
        is_done=False,
        created_at=now_vn()
    )
    db.session.add(reply_noti)

    # Đánh dấu feedback gốc là đã trả lời
    n.is_done = True
    n.title = f"✅ Đã trả lời: {n.title}"

    db.session.commit()

    flash(f"Đã gửi trả lời feedback cho user {target_user.username}.", "success")
    return redirect(url_for("notifications_page", id=n.id))

@app.route("/notifications/delete/<int:noti_id>")
@login_required
def notification_delete(noti_id):
    n = Notification.query.get_or_404(noti_id)

    if current_user.role == "admin":
        if n.role != "admin":
            abort(403)
    else:
        if n.role != "user" or n.user_id != current_user.id:
            abort(403)

    db.session.delete(n)
    db.session.commit()

    flash("Đã xóa thông báo.", "success")
    return redirect(url_for("notifications_page"))

@app.route("/notifications")
@login_required
def notifications_page():
    cleanup_old_notifications(30)
    selected_id = request.args.get("id", type=int)

    if current_user.role == "admin":
        notifications = (
            Notification.query
            .filter_by(role="admin")
            .order_by(Notification.created_at.desc(), Notification.id.desc())
            .all()
        )

        notifications = sorted(notifications, key=admin_notification_priority)

        user_options = (
            User.query
            .filter_by(role="user")
            .order_by(User.username.asc(), User.email.asc())
            .all()
        )
    else:
        notifications = (
            Notification.query
            .filter_by(role="user", user_id=current_user.id)
            .order_by(Notification.created_at.desc(), Notification.id.desc())
            .all()
        )
        user_options = []

    selected = None

    if notifications:
        if selected_id:
            selected = next((x for x in notifications if x.id == selected_id), None)
        if not selected:
            selected = notifications[0]

    if selected and not selected.is_read:
        selected.is_read = True
        db.session.commit()

    return render_template(
        "notifications.html",
        notifications=notifications,
        selected_notification=selected,
        user_options=user_options
    )


@app.route("/notifications/create", methods=["POST"])
@login_required
def notification_create():
    if current_user.role != "admin":
        abort(403)

    audience_type = (request.form.get("audience_type") or "").strip().lower()
    member_plan = (request.form.get("member_plan") or "").strip().upper()
    title = (request.form.get("title") or "").strip()


    message = (request.form.get("message") or "").strip()
    message_text = re.sub(r"<[^>]+>", "", message).strip()

    selected_user_ids = request.form.getlist("selected_user_ids")

    if not title:
        flash("Vui lòng nhập tiêu đề thông báo.", "danger")
        return redirect(url_for("notifications_page"))

    if not message or not message_text:
        flash("Vui lòng nhập nội dung thông báo.", "danger")
        return redirect(url_for("notifications_page"))

    users_query = User.query.filter_by(role="user")

    target_users = []

    if audience_type == "all":
        target_users = users_query.all()

    elif audience_type == "member":
        if not member_plan:
            flash("Vui lòng chọn gói thành viên.", "danger")
            return redirect(url_for("notifications_page"))

        # lọc theo member hoặc pending_member tùy hệ thống Ken đang dùng
        target_users = users_query.filter(
            db.or_(
                User.member == member_plan,
                User.pending_member == member_plan
            )
        ).all()

    elif audience_type == "select":
        if not selected_user_ids:
            flash("Vui lòng chọn ít nhất 1 user.", "danger")
            return redirect(url_for("notifications_page"))

        clean_ids = []
        for x in selected_user_ids:
            try:
                clean_ids.append(int(x))
            except:
                pass

        if not clean_ids:
            flash("Danh sách user chọn không hợp lệ.", "danger")
            return redirect(url_for("notifications_page"))

        target_users = users_query.filter(User.id.in_(clean_ids)).all()

    else:
        flash("Loại gửi thông báo không hợp lệ.", "danger")
        return redirect(url_for("notifications_page"))

    if not target_users:
        flash("Không tìm thấy user phù hợp để gửi thông báo.", "warning")
        return redirect(url_for("notifications_page"))

    created = 0

    for u in target_users:
        n = Notification(
            role="user",
            user_id=u.id,
            title=title,
            message=message,
            target_url=url_for("main"),
            icon="📢",
            is_read=False,
            action_type="general_notice",
            ref_user_id=u.id,
            is_done=False,
            created_at=now_vn()
        )
        db.session.add(n)
        created += 1

    db.session.commit()
    flash(f"Đã gửi thông báo cho {created} user.", "success")
    return redirect(url_for("notifications_page"))



def cleanup_old_notifications(days=30):
    cutoff = now_vn() - timedelta(days=days)

    try:
        old_items = Notification.query.filter(Notification.created_at < cutoff).all()
        if old_items:
            for n in old_items:
                db.session.delete(n)
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("[cleanup_old_notifications] ERROR:", e)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required():
    if not current_user.is_authenticated:
        abort(401)
    if (current_user.role or "").strip().lower() != "admin":
        abort(403)

def check_access_permission(user):
    # 🔐 ADMIN LUÔN ĐƯỢC PHÉP
    if user.role == "admin":
        return True

    setting = AccessSetting.query.first()
    if not setting:
        return True

    if setting.mode == "all":
        return True

    if setting.mode == "admin_only":
        return False

    if setting.mode == "custom":
        allowed_ids = {a.user_id for a in AccessAllow.query.all()}
        return user.id in allowed_ids

    return False



@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        password2 = request.form.get("password2", "").strip()

        # Validate cơ bản
        if not username or not password or not password2:
            flash("Vui lòng nhập đầy đủ thông tin.")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("Tên đăng nhập phải từ 3 ký tự trở lên.")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Mật khẩu phải từ 6 ký tự trở lên.")
            return redirect(url_for("register"))

        if password != password2:
            flash("Mật khẩu nhập lại không khớp.")
            return redirect(url_for("register"))

        # ✅ kiểm tra email hợp lệ
        if not is_valid_email(email):
            flash("❌ Email không hợp lệ. Vui lòng dùng Gmail, Yahoo, Outlook...")
            return redirect(url_for("register"))

        # ✅ kiểm tra trùng email
        if User.query.filter_by(email=email).first():
            flash("❌ Email đã được đăng ký.")
            return redirect(url_for("register"))


        # ✅ Kiểm tra trùng username (không phân biệt hoa thường)
        existed = User.query.filter(
            db.func.lower(User.username) == username.lower()
        ).first()
        if existed:
            flash("❌ Tên đăng nhập đã tồn tại. Hãy chọn tên khác.")
            return redirect(url_for("register"))


        # ❌ KHÔNG set trial ở đây nữa (trial chỉ bắt đầu khi kích hoạt)
        u = User(
            username=username,
            email=email,
            pw_hash=generate_password_hash(password),
            role="user",

            status="N/A",              # ✅ trống (hoặc "WAIT" nếu Ken thích)
            email_verified=False,
            trial_start=None,
            trial_end=None,

            member="Free",         # ✅ thêm dòng này sau khi tạo cột member (mục 4)
            pref_num_questions=DEFAULT_NUM_QUESTIONS,
            pref_time_per_q=DEFAULT_TIME_PER_Q
        )

        try:
            db.session.add(u)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("❌ Tên đăng nhập đã tồn tại. Hãy chọn tên khác.")
            return redirect(url_for("register"))

        # ✅ GỬI EMAIL KÍCH HOẠT (PHẢI NẰM SAU COMMIT THÀNH CÔNG)
        mail_ok = False
        try:
            mail_ok = send_activation_email(u)
        except Exception as e:
            print("[EMAIL] activation send error:", e)
            mail_ok = False

        # ✅ lưu sẵn để login.html mở popup hướng dẫn kích hoạt
        session["pending_activation_user_id"] = u.id
        session["pending_activation_hint"] = u.email

        if mail_ok:
            flash(
                "📩 Đăng ký thành công. Vui lòng vào email để bấm kích hoạt tài khoản trước khi đăng nhập.",
                "login_warning"
            )
        else:
            flash(
                "⚠️ Đăng ký thành công nhưng email kích hoạt chưa gửi được. Vui lòng bấm Gửi lại email kích hoạt ở trang đăng nhập.",
                "login_warning"
            )

        return redirect(url_for("login"))
    return render_template("register.html")




@app.route("/activate/<token>")
def activate_account(token):
    if not token:
        flash("❌ Link kích hoạt không hợp lệ.", "login_error")
        return redirect(url_for("login"))

    user = User.query.filter_by(activation_token=token).first()
    if not user:
        flash("❌ Link kích hoạt không đúng hoặc đã hết hiệu lực.", "login_error")
        return redirect(url_for("login"))

    # ✅ Nếu đã kích hoạt rồi
    if user.email_verified:
        flash("✅ Tài khoản đã được kích hoạt trước đó. Hãy đăng nhập.", "success")
        return redirect(url_for("login"))

    # ✅ KÍCH HOẠT + BẮT ĐẦU TRIAL
    now = datetime.now(timezone.utc)
    user.email_verified = True
    user.email_verified_at = now
    user.status = "active"

    user.trial_start = now
    user.trial_end = now + timedelta(days=TRIAL_DAYS_DEFAULT)

    # 🔥 xoá token để tránh bấm lại
    user.activation_token = None
    db.session.commit()

    session.pop("pending_activation_user_id", None)
    session.pop("pending_activation_hint", None)

    flash("✅ Kích hoạt tài khoản thành công! Bạn có thể đăng nhập ngay.", "success")
    return redirect(url_for("login"))




ALLOWED_PREVIEW_MEMBERS = {"free", "basic", "pro", "vip"}

def get_effective_member():
    """
    Member hiệu lực để render nội dung.
    - Admin bình thường: ADMIN
    - Admin đang preview: dùng gói preview
    - User thường: dùng member thật của user
    """
    if not current_user.is_authenticated:
        return "free"

    if getattr(current_user, "role", "") == "admin":
        preview_member = (session.get("admin_preview_member") or "").strip().lower()
        if preview_member in ALLOWED_PREVIEW_MEMBERS:
            return preview_member

        return "admin"

    return (getattr(current_user, "member", None) or "free").strip().lower()

def parse_member_plans(raw: str):
    return [x.strip().upper() for x in (raw or "").split(",") if x.strip()]

def can_access_plans(raw_plans: str) -> bool:
    """
    Rule:
    - Không set gói nào => ẩn
    - Admin full mode => thấy tất cả
    - Admin preview mode => lọc như user theo gói preview
    - Nếu plan có ADMIN => chỉ admin full mode mới thấy
    """
    plans = parse_member_plans(raw_plans)

    # không set gì => ẩn
    if not plans:
        return False

    role = getattr(current_user, "role", "").lower()

    # admin full quyền
    if role == "admin" and not is_admin_preview_mode():
        return True

    user_plan = norm_plan(get_effective_member())

    # user/admin preview không được dùng nội dung ADMIN-only
    if "ADMIN" in plans:
        return False

    return user_plan in plans

def is_admin_preview_mode():
    if not current_user.is_authenticated:
        return False
    if getattr(current_user, "role", "") != "admin":
        return False
    preview_member = (session.get("admin_preview_member") or "").strip().lower()
    return preview_member in ALLOWED_PREVIEW_MEMBERS


@app.before_request
def inject_preview_globals():
    g.effective_member = get_effective_member()
    g.is_admin_preview = is_admin_preview_mode()
    g.admin_preview_member = (session.get("admin_preview_member") or "").strip().lower()


@app.context_processor
def inject_preview_context():
    return {
        "effective_member": get_effective_member(),
        "is_admin_preview": is_admin_preview_mode(),
        "admin_preview_member": (session.get("admin_preview_member") or "").strip().lower(),
    }

@app.post("/admin/preview-member/set")
@login_required
def admin_set_preview_member():
    if getattr(current_user, "role", "") != "admin":
        return jsonify({"ok": False, "message": "Không có quyền"}), 403

    data = request.get_json(silent=True) or {}
    member = (data.get("member") or "").strip().lower()

    if member not in ALLOWED_PREVIEW_MEMBERS:
        return jsonify({"ok": False, "message": "Gói không hợp lệ"}), 400

    session["admin_preview_member"] = member
    session.modified = True

    return jsonify({
        "ok": True,
        "message": f"Đã chuyển sang chế độ xem gói {member.upper()}",
        "member": member
    })


@app.post("/admin/preview-member/clear")
@login_required
def admin_clear_preview_member():
    if getattr(current_user, "role", "") != "admin":
        return jsonify({"ok": False, "message": "Không có quyền"}), 403

    session.pop("admin_preview_member", None)
    session.modified = True

    return jsonify({
        "ok": True,
        "message": "Đã thoát chế độ xem thử"
    })



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        # ===== INPUT =====
        login_id = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        ip = request.remote_addr
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

        login_key_lc = login_id.lower()

        # ===== FIND USER (username hoặc email) =====
        u = User.query.filter(
            or_(
                func.lower(func.trim(User.username)) == login_key_lc,
                func.lower(func.trim(User.email)) == login_key_lc
            )
        ).first()

        # ===== WRONG LOGIN =====
        if (not u) or (not check_password_hash(u.pw_hash, password)):
            write_login_log_summary(login_id, ip, "failed")
            db.session.commit()

            if is_ajax:
                return jsonify({
                    "ok": False,
                    "message": "Sai tài khoản hoặc mật khẩu"
                }), 401

            flash("Sai tài khoản hoặc mật khẩu", "login_error")
            return redirect(url_for("login"))

        # ===== EMAIL NOT VERIFIED =====
        if u.role != "admin" and not getattr(u, "email_verified", False):
            write_login_log_summary(u.username, ip, "blocked")
            db.session.commit()

            session["pending_activation_user_id"] = u.id
            session["pending_activation_hint"] = u.email

            flash(
                "📩 Tài khoản chưa kích hoạt. Vui lòng kiểm tra email.",
                "login_warning"
            )

            if is_ajax:
                return jsonify({
                    "ok": False,
                    "redirect_url": url_for("login"),
                    "message": "Tài khoản chưa kích hoạt"
                }), 403

            return redirect(url_for("login"))

        # ===== STATUS CONTROL =====
        if u.role != "admin":
            st = (getattr(u, "status", "") or "").strip().upper()

            # ===== LOCK =====
            if st == "LOCK":
                write_login_log_summary(u.username, ip, "locked")
                db.session.commit()

                if is_ajax:
                    return jsonify({
                        "ok": False,
                        "status": "LOCK",
                        "message": "Tài khoản đã bị khóa."
                    }), 403

                return render_template(
                    "login.html",
                    locked=True,
                    locked_username=u.username,
                    member_plan_cards=build_member_plan_cards_for_user(u),
                    payment_bank_setting=get_active_bank_setting(),
                    play_intro=False
                )

            # ===== WAIT_ACCEPT =====
            if st in ("WAIT_ACCEPT", "WAIT-ACCEPT", "WAIT-ACCPET"):
                if st != "WAIT_ACCEPT":
                    u.status = "WAIT_ACCEPT"
                    db.session.commit()

                end = _to_utc_aware(u.trial_end)
                now = datetime.now(timezone.utc)

                if end and end > now:
                    u.status = "ACTIVE"
                    db.session.commit()
                else:
                    write_login_log_summary(u.username, ip, "wait_accept")
                    db.session.commit()
                    if is_ajax:
                        return jsonify({
                            "ok": False,
                            "status": "WAIT_ACCEPT",
                            "message": "Tài khoản đang chờ admin duyệt.",
                            "username": u.username,
                            "email": u.email
                        }), 403

                    return render_template(
                        "login.html",
                        wait_accept=True,
                        expired_username=u.username,
                        expired_email=u.email,
                        member_plan_cards=build_member_plan_cards_for_user(u),
                        payment_bank_setting=get_active_bank_setting(),
                        play_intro=False
                    )

            # ===== EXPIRED =====
            now = datetime.now(timezone.utc)
            end = _to_utc_aware(u.trial_end)

            if end and now > end:
                if st != "WAIT_RENEW":
                    u.status = "WAIT_RENEW"
                    db.session.add(u)

                write_login_log_summary(u.username, ip, "expired")
                db.session.commit()
                if is_ajax:
                    return jsonify({
                        "ok": False,
                        "status": "WAIT_RENEW",
                        "message": "Tài khoản đã hết hạn, vui lòng gia hạn gói.",
                        "username": u.username,
                        "email": u.email
                    }), 403

                return render_template(
                    "login.html",
                    wait_renew=True,
                    expired_username=u.username,
                    expired_email=u.email,
                    member_plan_cards=build_member_plan_cards_for_user(u),
                    payment_bank_setting=get_active_bank_setting(),
                    play_intro=False
                )

            # ===== WAIT_RENEW =====
            if st == "WAIT_RENEW":
                write_login_log_summary(u.username, ip, "wait_renew")
                db.session.commit()

                if is_ajax:
                    return jsonify({
                        "ok": False,
                        "status": "WAIT_RENEW",
                        "message": "Tài khoản đang chờ gia hạn.",
                        "username": u.username,
                        "email": u.email
                    }), 403

                return render_template(
                    "login.html",
                    wait_renew=True,
                    expired_username=u.username,
                    expired_email=u.email,
                    member_plan_cards=build_member_plan_cards_for_user(u),
                    payment_bank_setting=get_active_bank_setting(),
                    play_intro=False
                )

            # ===== UNKNOWN STATUS =====
            if st not in ("", "ACTIVE"):
                write_login_log_summary(u.username, ip, "blocked")
                db.session.commit()

                if is_ajax:
                    return jsonify({
                        "ok": False,
                        "status": "LOCK",
                        "message": "Tài khoản hiện không thể đăng nhập."
                    }), 403

                return render_template(
                    "login.html",
                    locked=True,
                    locked_username=u.username,
                    member_plan_cards=build_member_plan_cards_for_user(u),
                    payment_bank_setting=get_active_bank_setting(),
                    play_intro=False
                )

        # ===== LOGIN SUCCESS =====
        login_user(u)

        if getattr(u, "must_change_password", False):
            write_login_log_summary(u.username, ip, "success")
            db.session.commit()
            flash("🔐 Vui lòng đổi mật khẩu.", "login_warning")
            return redirect(url_for("account"))

        write_login_log_summary(u.username, ip, "success")
        db.session.commit()

        if is_ajax:
            return jsonify({"ok": True})

        session["play_intro"] = True
        return redirect(url_for("login"))

    # ===== GET =====
    if request.method == "GET":

        # ===== mở popup WAIT_ACCEPT từ session =====
        if request.args.get("wait_accept") == "1":
            username = session.get("wait_accept_username", "")
            email = session.get("wait_accept_email", "")

            target_user = None

            if username:
                target_user = User.query.filter_by(username=username).first()

            if not target_user and email:
                target_user = User.query.filter_by(email=email).first()

            return render_template(
                "login.html",
                wait_accept=True,
                expired_username=username or "",
                expired_email=email or "",
                member_plan_cards=build_member_plan_cards_for_user(target_user) if target_user else [],
                payment_bank_setting=get_active_bank_setting(),
                play_intro=False
            )

        # ===== GET NORMAL =====
        play_intro = session.pop("play_intro", False)

        return render_template(
            "login.html",
            member_plan_cards=[],
            payment_bank_setting=get_active_bank_setting(),
            play_intro=play_intro
        )


def apply_approved_membership(user, new_plan_code: str, months: int):
    """
    Rule:
    1. Hết hạn mới mua lại -> bắt đầu từ lúc admin duyệt
    2. Còn hạn + cùng gói -> cộng dồn từ trial_end hiện tại
    3. Còn hạn + nâng/hạ gói -> bắt đầu gói mới từ lúc admin duyệt, không cộng dồn
    """
    approved_at = now_vn()
    now = _to_utc_aware(approved_at)

    old_plan_code = norm_plan(user.pending_member or user.member or "FREE")
    new_plan_code = norm_plan(new_plan_code)

    current_end = _to_utc_aware(user.trial_end) if user.trial_end else None
    still_active = bool(current_end and current_end > now)

    # Case 1: đã hết hạn
    if not still_active:
        user.trial_start = approved_at
        user.trial_end = add_months_exact(approved_at, months)

    # Case 2: còn hạn + cùng gói => cộng dồn
    elif old_plan_code == new_plan_code:
        base_end = user.trial_end if user.trial_end else approved_at
        user.trial_end = add_months_exact(base_end, months)

        if not user.trial_start:
            user.trial_start = approved_at

    # Case 3 + 4: còn hạn + đổi gói => không cộng dồn
    else:
        user.trial_start = approved_at
        user.trial_end = add_months_exact(approved_at, months)

    user.status = "ACTIVE"
    user.member = new_plan_code

    return approved_at

@app.get("/renew/approve/<token>")
def renew_approve(token):
    user = User.query.filter_by(pending_approve_token=token).first()
    if not user:
        return "Link không hợp lệ hoặc đã được duyệt.", 400

    plan_code = norm_plan(user.pending_plan_code or user.member or "FREE")
    months = int(user.pending_months or 1)

    apply_approved_membership(user, plan_code, months)

    # clear pending
    user.pending_approve_token = None
    user.pending_plan_code = None
    user.pending_member = None
    user.pending_member_name = None
    user.pending_months = None
    user.pending_amount = None
    user.pending_discount = None
    user.pending_final_total = None
    user.pending_duration_label = None
    user.pending_memo = None
    user.pending_at = None

    db.session.commit()

    # gửi mail user: đã duyệt
    try:
        if user.email:
            html_ok = build_user_approved_email(
                username=user.username,
                plan_code=plan_code,
                months=months,
                trial_start=user.trial_start,
                trial_end=user.trial_end
            )
            send_email(user.email, "Thanh toán đã được duyệt - Taekwondo", html_ok)
    except Exception as e:
        print("[renew_approve] send_mail failed:", e)

    return f"""
    <!doctype html>
    <html lang="vi">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Duyệt gia hạn thành công</title>
    </head>
    <body style="
      margin:0;
      padding:0;
      font-family:Arial,sans-serif;
      background:linear-gradient(180deg,#fff7ed 0%, #f8fafc 100%);
      color:#1f2937;
    ">

      <div style="
        min-height:100vh;
        display:flex;
        align-items:center;
        justify-content:center;
        padding:24px;
        box-sizing:border-box;
      ">
        <div style="
          width:min(760px, 96vw);
          background:#ffffff;
          border-radius:24px;
          overflow:hidden;
          box-shadow:0 25px 80px rgba(0,0,0,.16);
          border:1px solid #e5e7eb;
        ">

          <div style="
            background:linear-gradient(135deg,#f97316,#ea580c);
            padding:26px 28px;
            color:#fff;
          ">
            <div style="
              display:flex;
              align-items:center;
              gap:14px;
            ">
              <div style="
                width:58px;
                height:58px;
                border-radius:18px;
                background:rgba(255,255,255,.16);
                display:flex;
                align-items:center;
                justify-content:center;
                font-size:30px;
                font-weight:900;
                border:1px solid rgba(255,255,255,.24);
              ">✅</div>

              <div>
                <div style="font-size:30px;font-weight:900;line-height:1.15;">
                  Đã duyệt thành công
                </div>
                <div style="margin-top:6px;font-size:14px;opacity:.95;">
                  User đã được kích hoạt gói học và bắt đầu tính thời gian sử dụng
                </div>
              </div>
            </div>
          </div>

          <div style="padding:28px;">

            <div style="
              display:inline-flex;
              align-items:center;
              gap:8px;
              padding:8px 14px;
              border-radius:999px;
              background:#dcfce7;
              color:#166534;
              font-weight:800;
              border:1px solid #bbf7d0;
              margin-bottom:18px;
            ">
              Trạng thái: ACTIVE
            </div>

            <div style="
              display:grid;
              grid-template-columns:1fr;
              gap:16px;
            ">

              <div style="
                background:#f8fafc;
                border:1px solid #e5e7eb;
                border-radius:18px;
                padding:18px;
              ">
                <div style="font-size:15px;font-weight:900;color:#111827;margin-bottom:14px;">
                  Thông tin user
                </div>

                <div style="display:grid;grid-template-columns:110px 1fr;gap:10px 12px;font-size:15px;line-height:1.6;">
                  <div style="color:#6b7280;font-weight:800;">Username</div>
                  <div><b>{user.username}</b></div>

                  <div style="color:#6b7280;font-weight:800;">Gói học</div>
                  <div><b>{plan_display(plan_code)}</b> ({plan_code})</div>

                  <div style="color:#6b7280;font-weight:800;">Số tháng</div>
                  <div><b>{months}</b></div>
                </div>
              </div>

              <div style="
                background:#f8fafc;
                border:1px solid #e5e7eb;
                border-radius:18px;
                padding:18px;
              ">
                <div style="font-size:15px;font-weight:900;color:#111827;margin-bottom:14px;">
                  Thời gian sử dụng
                </div>

                <div style="display:grid;grid-template-columns:110px 1fr;gap:10px 12px;font-size:15px;line-height:1.6;">
                  <div style="color:#6b7280;font-weight:800;">Bắt đầu</div>
                  <div><b>{user.trial_start.strftime("%d/%m/%Y %H:%M:%S")}</b></div>

                  <div style="color:#6b7280;font-weight:800;">Hết hạn</div>
                  <div><b>{user.trial_end.strftime("%d/%m/%Y %H:%M:%S")}</b></div>
                </div>
              </div>
            </div>

            <div style="
              margin-top:18px;
              padding:16px 18px;
              border-radius:16px;
              background:#eff6ff;
              border:1px solid #dbeafe;
              color:#1e3a8a;
              line-height:1.6;
              font-size:14px;
            ">
              Hệ thống đã cập nhật thời gian sử dụng theo đúng thời điểm admin bấm duyệt.
              User có thể đăng nhập và sử dụng hệ thống ngay.
            </div>

            <div style="
              display:flex;
              flex-wrap:wrap;
              gap:12px;
              margin-top:22px;
            ">
              <a href="/login" style="
                display:inline-flex;
                align-items:center;
                justify-content:center;
                min-width:180px;
                padding:13px 18px;
                border-radius:14px;
                background:#2563eb;
                color:#fff;
                text-decoration:none;
                font-weight:900;
                box-shadow:0 10px 24px rgba(37,99,235,.22);
              ">
                Về trang đăng nhập
              </a>

              <button onclick="window.close()" style="
                display:inline-flex;
                align-items:center;
                justify-content:center;
                min-width:150px;
                padding:13px 18px;
                border-radius:14px;
                background:#fff;
                color:#374151;
                border:1px solid #d1d5db;
                font-weight:900;
                cursor:pointer;
              ">
                Đóng trang này
              </button>
            </div>
          </div>

          <div style="
            padding:16px 28px;
            border-top:1px solid #e5e7eb;
            background:#f9fafb;
            color:#6b7280;
            font-size:13px;
          ">
            Hệ thống học tập Taekwondo • Xác nhận duyệt gia hạn thành công
          </div>
        </div>
      </div>

    </body>
    </html>
    """

@app.route("/resend-activation")
def resend_activation():
    q = (request.args.get("q") or "").strip()
    uid = session.get("pending_activation_user_id")

    user = None

    # ✅ Ưu tiên: nếu session có uid => resend luôn
    if uid:
        user = User.query.get(uid)

    # ✅ Nếu không có uid hoặc uid lỗi, fallback theo q (username/email)
    if not user and q:
        user = User.query.filter(or_(User.username == q, User.email == q)).first()

    if not user:
        flash("⚠️ Không xác định được tài khoản để gửi lại email kích hoạt.", "login_warning")
        return redirect(url_for("login"))

    if user.email_verified:
        # ✅ đã kích hoạt rồi thì xóa session
        session.pop("pending_activation_user_id", None)
        session.pop("pending_activation_hint", None)
        flash("✅ Tài khoản đã được kích hoạt. Bạn có thể đăng nhập.", "success")
        return redirect(url_for("login"))

    try:
        send_activation_email(user)
        flash("📩 Đã gửi lại email kích hoạt. Vui lòng kiểm tra hộp thư (kể cả Spam/Quảng cáo).", "success")
    except Exception as e:
        print("[resend_activation] error:", e)
        flash("⚠️ Gửi email kích hoạt thất bại. Vui lòng thử lại sau.", "login_warning")

    return redirect(url_for("login"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form.get("email", "").strip().lower()

    user = User.query.filter_by(email=email).first()

    if not user:
        flash("❌ Email này chưa được đăng ký.", "danger")
        return redirect(url_for("login"))

    # tạo mật khẩu mới
    new_pass = secrets.token_hex(4)
    user.pw_hash = generate_password_hash(new_pass)
    user.must_change_password = True   # ✅ ĐÁNH DẤU
    db.session.commit()

    html = render_template(
        "base_email.html",
        title="Khôi phục mật khẩu",
        preheader="Mật khẩu mới đã được tạo cho tài khoản của bạn.",
        username=user.username,
        current_year=datetime.now().year,

        # các biến header/footer Ken đã làm
        brand_name="Hệ thống học tập Taekwondo",
        brand_url=BASE_URL,        # VD: "http://127.0.0.1:5000/"
        logo_url=LOGO_URL,         # nếu còn dùng
        header_right_text="",
        brand_address="TP.HCM, Việt Nam",
        support_email="silentnight1993pro@gmail.com",
        unsubscribe_url=None,

        # ===== BODY THEO FORMAT KEN MUỐN =====
        message_html=f"""
          <p style="margin:0 0 10px;">Xin chào, <strong>{user.username}</strong>!</p>

          <p style="margin:0 0 12px;">
            Xin cảm ơn bạn đã tin tưởng và sử dụng hệ thống học tập Taekwondo.
          </p>

          <div style="
            margin:14px 0 14px;
            padding:12px 14px;
            background:#f9fafb;
            border:1px solid #e5e7eb;
            border-radius:12px;
            line-height:1.7;
          ">
            <div><strong>ID:</strong> {user.username}</div>
            <div style="margin-top:4px;">
              <strong>Mật khẩu:</strong>
              <span style="font-size:16px; font-weight:800; color:#1d4ed8;">{new_pass}</span>
            </div>
          </div>

          <p style="margin:0 0 8px;">
            Chúc các bạn có những buổi học và ôn tập thật thú vị.
          </p>

          <p style="margin:0;">
            Xin vui lòng không được tiết lộ hoặc chia sẻ tên ID hoặc mật khẩu cho người khác,
            để tránh các trường hợp bị mất thông tin.
          </p>

          <p style="margin:10px 0 0;">Xin cảm ơn!</p>
        """,

        button_text="Vào trang web",
        button_url=get_base_url(),

        # note_html: bỏ hoặc để ngắn (vì nội dung chính đã có)
        note_html=None
    )

    send_email(email, "Khôi phục mật khẩu – Hệ thống học tập Taekwondo", html)
    flash("✅ Vui lòng kiểm tra email để nhận lại thông tin đăng nhập.", "success")
    return redirect(url_for("login"))






@app.route("/account/change-email", methods=["POST"])
@login_required
def change_email():
    current_email = (request.form.get("current_email") or "").strip().lower()
    new_email = (request.form.get("new_email") or "").strip().lower()

    if not current_email or not new_email:
        flash("❌ Vui lòng nhập đầy đủ email hiện tại và email mới.", "danger_email")
        return redirect(url_for("account"))

    user_email = (current_user.email or "").strip().lower()
    if current_email != user_email:
        flash("❌ Email hiện tại không đúng.", "danger_email")
        return redirect(url_for("account"))

    if new_email == user_email:
        flash("❌ Email mới phải khác email hiện tại.", "danger_email")
        return redirect(url_for("account"))

    existed = User.query.filter(User.email.ilike(new_email), User.id != current_user.id).first()
    if existed:
        flash("❌ Email mới đã được sử dụng.", "danger_email")
        return redirect(url_for("account"))

    current_user.email = new_email
    db.session.commit()

    flash("✅ Đổi email thành công.", "success_email")
    return redirect(url_for("account"))


# ===================== PAGES =====================

@app.route("/")
def home():
    return redirect(url_for("main"))

# =====================================================
# MAIN ROUTES MỚI – URL ĐẸP
# =====================================================

def get_active_edu_folder_by_slug(level, slug, parent_id=None):
    slug = slugify(slug or "")

    q = EduFolder.query.filter_by(level=level, is_active=1)

    if parent_id is None:
        q = q.filter(EduFolder.parent_id.is_(None))
    else:
        q = q.filter_by(parent_id=parent_id)

    for f in q.order_by(EduFolder.order.asc(), EduFolder.id.asc()).all():
        if slugify(f.name) == slug:
            return f
    return None


def get_active_practice_folder_by_slug(level, slug, parent_id=None):
    slug = slugify(slug or "")

    q = Folder.query.filter_by(level=level)

    if parent_id is None:
        q = q.filter(Folder.parent_id.is_(None))
    else:
        q = q.filter_by(parent_id=parent_id)

    for f in q.order_by(Folder.order_index.asc()).all():
        if slugify(f.name) == slug:
            return f
    return None


@app.route("/main/hoc/<edu1_slug>")
@login_required
def main_edu_level1(edu1_slug):
    edu1 = get_active_edu_folder_by_slug(level=1, slug=edu1_slug)
    if not edu1:
        abort(404)

    raw_children = (
        EduFolder.query
        .filter_by(parent_id=edu1.id, is_active=1)
        .order_by(EduFolder.order.asc(), EduFolder.id.asc())
        .all()
    )

    edu_folders = []
    for f in raw_children:
        edu_folders.append({
            "id": f.id,
            "name": f.name,
            "image": f.image,
            "level": f.level,
            "url": url_for(
                "main_edu_level2",
                edu1_slug=slugify(edu1.name),
                edu2_slug=slugify(f.name)
            )
        })

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("main")},
        {"name": "Học Taekwondo", "url": url_for("main")},
        {"name": edu1.name, "url": None},
    ]

    return render_template(
        "folder_list.html",
        page_title=edu1.name,
        edu_folders=edu_folders,
        lessons=[],
        items=[],
        breadcrumbs=breadcrumbs,
        mode="edu"
    )


@app.route("/main/hoc/<edu1_slug>/<edu2_slug>")
@login_required
def main_edu_level2(edu1_slug, edu2_slug):
    edu1 = get_active_edu_folder_by_slug(level=1, slug=edu1_slug)
    if not edu1:
        abort(404)

    edu2 = get_active_edu_folder_by_slug(level=2, slug=edu2_slug, parent_id=edu1.id)
    if not edu2:
        abort(404)

    raw_children = (
        EduFolder.query
        .filter_by(parent_id=edu2.id, is_active=1)
        .order_by(EduFolder.order.asc(), EduFolder.id.asc())
        .all()
    )

    edu_folders = []
    for f in raw_children:
        edu_folders.append({
            "id": f.id,
            "name": f.name,
            "image": f.image,
            "level": f.level,
            "url": url_for(
                "main_edu_level3",
                edu1_slug=slugify(edu1.name),
                edu2_slug=slugify(edu2.name),
                edu3_slug=slugify(f.name)
            )
        })

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("main")},
        {"name": "Học Taekwondo", "url": url_for("main")},
        {"name": edu1.name, "url": url_for("main_edu_level1", edu1_slug=edu1_slug)},
        {"name": edu2.name, "url": None},
    ]

    return render_template(
        "folder_list.html",
        page_title=edu2.name,
        edu_folders=edu_folders,
        lessons=[],
        items=[],
        breadcrumbs=breadcrumbs,
        mode="edu"
    )


@app.route("/main/hoc/<edu1_slug>/<edu2_slug>/<edu3_slug>")
@login_required
def main_edu_level3(edu1_slug, edu2_slug, edu3_slug):
    edu1 = get_active_edu_folder_by_slug(level=1, slug=edu1_slug)
    if not edu1:
        abort(404)

    edu2 = get_active_edu_folder_by_slug(level=2, slug=edu2_slug, parent_id=edu1.id)
    if not edu2:
        abort(404)

    edu3 = get_active_edu_folder_by_slug(level=3, slug=edu3_slug, parent_id=edu2.id)
    if not edu3:
        abort(404)

    lessons = load_lessons_by_folder3(edu3.id)

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("main")},
        {"name": "Học Taekwondo", "url": url_for("main")},
        {"name": edu1.name, "url": url_for("main_edu_level1", edu1_slug=edu1_slug)},
        {"name": edu2.name, "url": url_for("main_edu_level2", edu1_slug=edu1_slug, edu2_slug=edu2_slug)},
        {"name": edu3.name, "url": None},
    ]

    return render_template(
        "folder_list.html",
        page_title=edu3.name,
        edu_folders=[],
        lessons=lessons,
        items=[],
        breadcrumbs=breadcrumbs,
        mode="edu"
    )


@app.route("/main/on-tap/<slug1>")
@login_required
def practice_level1(slug1):
    f1 = get_active_practice_folder_by_slug(level=1, slug=slug1)
    if not f1:
        abort(404)

    if not has_accessible_folder3_under_folder1(f1.id):
        abort(404)

    all_folder2 = (
        Folder.query
        .filter_by(level=2, parent_id=f1.id)
        .order_by(Folder.order_index.asc())
        .all()
    )

    folder2_list = [f2 for f2 in all_folder2 if has_accessible_folder3_under_folder2(f2.id)]

    items = [{
        "name": f.name,
        "image": url_for("static", filename=f.image) if f.image else None,
        "url": url_for("practice_level2", slug1=slug1, slug2=slugify(f.name))
    } for f in folder2_list]

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("main")},
        {"name": "Ôn tập", "url": url_for("main")},
        {"name": f1.name, "url": None},
    ]

    return render_template(
        "folder_list.html",
        page_title=f1.name,
        items=items,
        breadcrumbs=breadcrumbs,
        mode="practice",
        edu_folders=[],
        lessons=[]
    )


@app.route("/main/on-tap/<slug1>/<slug2>")
@login_required
def practice_level2(slug1, slug2):
    f1 = get_active_practice_folder_by_slug(level=1, slug=slug1)
    if not f1:
        abort(404)

    f2 = get_active_practice_folder_by_slug(level=2, slug=slug2, parent_id=f1.id)
    if not f2:
        abort(404)

    if not has_accessible_folder3_under_folder2(f2.id):
        abort(404)

    all_folder3 = (
        Folder.query
        .filter_by(level=3, parent_id=f2.id, is_active_practice=1)
        .order_by(Folder.order_index.asc())
        .all()
    )

    folder3_list = [f3 for f3 in all_folder3 if can_access_plans(f3.member_plans)]

    items = [{
        "name": f.name,
        "image": url_for("static", filename=f.image) if f.image else None,
        "url": url_for("practice_level3", slug1=slug1, slug2=slug2, slug3=slugify(f.name))
    } for f in folder3_list]

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("main")},
        {"name": "Ôn tập", "url": url_for("main")},
        {"name": f1.name, "url": url_for("practice_level1", slug1=slug1)},
        {"name": f2.name, "url": None},
    ]

    return render_template(
        "folder_list.html",
        page_title=f2.name,
        items=items,
        breadcrumbs=breadcrumbs,
        mode="practice",
        edu_folders=[],
        lessons=[]
    )


@app.route("/main/on-tap/<slug1>/<slug2>/<slug3>")
@login_required
def practice_level3(slug1, slug2, slug3):
    f1 = get_active_practice_folder_by_slug(level=1, slug=slug1)
    if not f1:
        abort(404)

    f2 = get_active_practice_folder_by_slug(level=2, slug=slug2, parent_id=f1.id)
    if not f2:
        abort(404)

    f3 = get_active_practice_folder_by_slug(level=3, slug=slug3, parent_id=f2.id)
    if not f3:
        abort(404)

    if not f3.is_active_practice:
        abort(404)

    if not can_access_plans(f3.member_plans):
        abort(404)

    return render_template(
        "quiz_prepare.html",
        topic_name=f3.name,
        start_url=url_for("quiz_start_folder", folder3_id=f3.id)
    )

@app.route("/sets")
@login_required
def sets_redirect():
    return redirect(url_for("main"))


@app.route("/main")
@login_required
def main():
    mode = "home"   # home | edu | practice

    # ===============================
    # HỌC TAEKWONDO – EDU FOLDER
    # ===============================
    edu_parent_id = request.args.get("edu_id", type=int)
    if edu_parent_id:
        mode = "edu"

    edu_current = None
    edu_parent = None
    edu_root = None
    lessons = []

    if edu_parent_id:
        edu_current = (
            EduFolder.query
            .filter(
                EduFolder.id == edu_parent_id,
                EduFolder.is_active == 1
            )
            .first()
        )

        if not edu_current:
            abort(404)

        edu_parent = edu_current.parent
        if edu_parent:
            edu_root = edu_parent.parent

        # Nếu là cấp 3 thì load bài học
        if edu_current.level == 3:
            lessons = load_lessons_by_folder3(edu_current.id)

    # ===============================
    # LOAD EDU FOLDER (CẤP CON)
    # ===============================
    if edu_parent_id:
        raw_edu_folders = (
            EduFolder.query
            .filter(
                EduFolder.parent_id == edu_parent_id,
                EduFolder.is_active == 1
            )
            .order_by(EduFolder.order.asc(), EduFolder.id.asc())
            .all()
        )
    else:
        raw_edu_folders = (
            EduFolder.query
            .filter(
                EduFolder.level == 1,
                EduFolder.is_active == 1
            )
            .order_by(EduFolder.order.asc(), EduFolder.id.asc())
            .all()
        )

    # ===============================
    # BUILD EDU URL ĐẸP CHO TEMPLATE
    # ===============================
    edu_folders = []

    for f in raw_edu_folders:
        item = {
            "id": f.id,
            "name": f.name,
            "image": f.image,
            "level": f.level,
            "url": url_for("main", edu_id=f.id)  # fallback
        }

        # Trang chủ -> cấp 1
        if not edu_parent_id and f.level == 1:
            item["url"] = url_for(
                "main_edu_level1",
                edu1_slug=slugify(f.name)
            )

        # Đang đứng ở cấp 1 -> đi cấp 2
        elif edu_current and edu_current.level == 1 and f.level == 2:
            item["url"] = url_for(
                "main_edu_level2",
                edu1_slug=slugify(edu_current.name),
                edu2_slug=slugify(f.name)
            )

        # Đang đứng ở cấp 2 -> đi cấp 3
        elif edu_current and edu_current.level == 2 and f.level == 3:
            if edu_current.parent:
                item["url"] = url_for(
                    "main_edu_level3",
                    edu1_slug=slugify(edu_current.parent.name),
                    edu2_slug=slugify(edu_current.name),
                    edu3_slug=slugify(f.name)
                )

        edu_folders.append(item)

    # ===============================
    # ÔN TẬP – FOLDER CẤP 1
    # Chỉ hiện folder1 còn ít nhất 1 folder3 hợp lệ
    # ===============================
    all_folder1 = (
        Folder.query
        .filter_by(level=1)
        .order_by(Folder.order_index)
        .all()
    )

    folder1_list = [
        f1 for f1 in all_folder1
        if has_accessible_folder3_under_folder1(f1.id)
    ]

    items = [{
        "name": f.name,
        "image": url_for("static", filename=f.image) if f.image else None,
        "url": url_for("practice_level1", slug1=slugify(f.name))
    } for f in folder1_list]

    # ===============================
    # BREADCRUMB
    # ===============================
    if edu_parent_id:
        breadcrumbs = build_edu_breadcrumb(
            edu_root=edu_root,
            edu_parent=edu_parent,
            edu_current=edu_current
        )
    else:
        breadcrumbs = build_home_breadcrumb()

    # ===============================
    # RENDER
    # ===============================
    return render_template(
        "folder_list.html",
        page_title="Trang chủ" if not edu_current else edu_current.name,
        edu_folders=edu_folders,
        lessons=lessons,
        items=items,
        breadcrumbs=breadcrumbs,
        mode=mode
    )


@app.route("/set/<int:folder1_id>", defaults={"folder2_id": None})
@app.route("/set/<int:folder1_id>/<int:folder2_id>")
@login_required
def view_set(folder1_id, folder2_id):
    f1 = Folder.query.get_or_404(folder1_id)

    # Nếu folder1 này không còn nội dung hợp lệ thì chặn luôn
    if not has_accessible_folder3_under_folder1(f1.id):
        abort(404)

    # ===============================
    # FOLDER 2
    # ===============================
    if folder2_id is None:
        all_folder2 = (
            Folder.query
            .filter_by(level=2, parent_id=folder1_id)
            .order_by(Folder.order_index)
            .all()
        )

        folder2_list = [
            f2 for f2 in all_folder2
            if has_accessible_folder3_under_folder2(f2.id)
        ]

        if not folder2_list:
            abort(404)

        items = []
        for f in folder2_list:
            items.append({
                "name": f.name,
                "image": url_for("static", filename=f.image) if f.image else None,
                "url": url_for(
                    "view_set",
                    folder1_id=folder1_id,
                    folder2_id=f.id
                )
            })

        breadcrumbs = build_practice_breadcrumb(
            folder1=f1,
            folder2=None
        )

        return render_template(
            "folder_list.html",
            page_title=f1.name,
            items=items,
            breadcrumbs=breadcrumbs,
            mode="practice",
            edu_folders=[],
            lessons=[]
        )

    # ===============================
    # FOLDER 3
    # ===============================
    f2 = Folder.query.filter_by(
        id=folder2_id,
        parent_id=f1.id,
        level=2
    ).first_or_404()

    if not has_accessible_folder3_under_folder2(f2.id):
        abort(404)

    all_folder3 = (
        Folder.query
        .filter_by(
            level=3,
            parent_id=f2.id,
            is_active_practice=1
        )
        .order_by(Folder.order_index.asc())
        .all()
    )

    folder3_list = [
        f3 for f3 in all_folder3
        if can_access_plans(f3.member_plans)
    ]

    if not folder3_list:
        abort(404)

    # Nếu chỉ có 1 folder3 thì chuyển thẳng
    if len(folder3_list) == 1:
        f3 = folder3_list[0]
        return redirect(
            f"/{slugify(f1.name)}/{slugify(f2.name)}/{slugify(f3.name)}"
        )

    items = []
    for f3 in folder3_list:
        items.append({
            "name": f3.name,
            "image": url_for("static", filename=f3.image) if f3.image else None,
            "url": url_for("quiz_prepare", folder3_id=f3.id)
        })

    breadcrumbs = build_practice_breadcrumb(
        folder1=f1,
        folder2=f2
    )

    return render_template(
        "folder_list.html",
        page_title=f2.name,
        items=items,
        breadcrumbs=breadcrumbs,
        mode="practice",
        edu_folders=[],
        lessons=[]
    )


@app.route("/quiz/prepare/<int:folder3_id>")
@login_required
def quiz_prepare(folder3_id):
    f3 = Folder.query.filter_by(id=folder3_id).first()
    if not f3:
        return f"Không tìm thấy folder3 id={folder3_id}", 404

    if not f3.is_active_practice:
        return "Folder này đang tắt ôn tập", 404

    if not can_access_plans(f3.member_plans):
        return "Tài khoản hiện tại không có quyền", 404

    return render_template(
        "quiz_prepare.html",
        topic_name=f3.name,
        start_url=url_for("quiz_start_folder", folder3_id=f3.id)
    )



# ===============================
# BREADCRUMB BUILDERS (CHUẨN)
# ===============================

def get_next_edu_order(level, parent_id=None):
    """
    Trả về order tiếp theo cho EduFolder
    - Level 1: parent_id = None
    - Level 2,3: parent_id = id cha
    """
    q = EduFolder.query.filter_by(level=level)

    if parent_id is None:
        q = q.filter(EduFolder.parent_id.is_(None))
    else:
        q = q.filter_by(parent_id=parent_id)

    max_order = q.with_entities(db.func.max(EduFolder.order)).scalar()

    return (max_order or 0) + 1


def build_home_breadcrumb():
    return [
        {"name": "Trang chủ", "url": None}
    ]


def build_edu_breadcrumb(edu_root=None, edu_parent=None, edu_current=None):
    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("main")},
        {"name": "Học Taekwondo", "url": url_for("main")}
    ]

    # Nếu đang ở cấp 1
    if edu_current and edu_current.level == 1:
        breadcrumbs.append({
            "name": edu_current.name,
            "url": None
        })
        return breadcrumbs

    # Nếu có root cấp 1
    if edu_root:
        breadcrumbs.append({
            "name": edu_root.name,
            "url": url_for("sets", edu_id=edu_root.id)
        })

    # Nếu có parent cấp 2
    if edu_parent:
        breadcrumbs.append({
            "name": edu_parent.name,
            "url": url_for("sets", edu_id=edu_parent.id)
        })

    # Current cuối cùng
    if edu_current:
        breadcrumbs.append({
            "name": edu_current.name,
            "url": None
        })

    return breadcrumbs


def build_practice_breadcrumb(folder1=None, folder2=None):
    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("main")},
        {"name": "Ôn tập", "url": url_for("main")}
    ]

    if folder1:
        breadcrumbs.append({
            "name": folder1.name,
            "url": None if folder2 is None else url_for("view_set", folder1_id=folder1.id)
        })

    if folder2:
        breadcrumbs.append({
            "name": folder2.name,
            "url": None
        })

    return breadcrumbs










@app.route("/quiz/start/<int:topic_id>")
@login_required
def quiz_start(topic_id):
    # ✅ Lấy topic
    topic = Topic.query.get_or_404(topic_id)

    # (nếu Ken chưa dùng 3 biến này thì có thể giữ hoặc xoá đều OK)
    folder1_id = request.args.get("folder1_id", type=int)
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    # =========================
    # ✅ SỐ CÂU HỎI
    # None = làm hết, không lặp
    # =========================
    num_questions = current_user.pref_num_questions

    if num_questions is None:
        # lấy tổng số câu trong topic
        total_q = Question.query.filter_by(topic_id=topic.id).count()
        final_count = total_q
    else:
        final_count = num_questions

    # =========================
    # ✅ THỜI GIAN / CÂU
    # None = không tính giờ
    # =========================
    time_per_q = current_user.pref_time_per_q

    # =========================
    # ✅ TẠO ATTEMPT
    # =========================
    attempt = Attempt(
        user_id=current_user.id,
        topic_id=topic.id,                 # luôn có
        created_at=datetime.now(timezone.utc),
        question_count=final_count,        # ❌ KHÔNG hardcode 10 nữa
        time_per_q=time_per_q              # None hoặc số
    )

    db.session.add(attempt)
    db.session.commit()

    return redirect(url_for("quiz_do", attempt_id=attempt.id))

@app.route("/quiz/start_folder/<int:folder3_id>")
@login_required
def quiz_start_folder(folder3_id):
    f3 = Folder.query.get_or_404(folder3_id)

    if f3.level != 3:
        return "Folder không hợp lệ (phải là cấp 3).", 400

    if not f3.is_active_practice:
        abort(404)

    if not can_access_plans(f3.member_plans):
        abort(404)

    num_questions = current_user.pref_num_questions
    time_per_q = current_user.pref_time_per_q

    all_qs = Question.query.filter_by(folder_id=folder3_id).all()
    qs = [q for q in all_qs if can_access_plans(q.member_plans)]

    if not qs:
        flash("Chủ đề này chưa có câu hỏi. Hãy quay lại bài học sau.", "danger")
        folder1_id = None
        if f3.parent and f3.parent.parent:
            folder1_id = f3.parent.parent.id
        return redirect(url_for("view_set", folder1_id=folder1_id))

    random.shuffle(qs)

    if num_questions is None:
        chosen_qs = qs
        final_count = len(qs)
    else:
        n = int(num_questions)
        if len(qs) >= n:
            chosen_qs = qs[:n]
        else:
            chosen_qs = list(qs)
            need = n - len(qs)
            chosen_qs.extend(random.choices(qs, k=need))
        final_count = n

    default_topic = Topic.query.first()
    if not default_topic:
        default_set = Set.query.first()
        if not default_set:
            default_set = Set(title="Bộ mặc định")
            db.session.add(default_set)
            db.session.commit()

        default_topic = Topic(set_id=default_set.id, name="Tổng hợp")
        db.session.add(default_topic)
        db.session.commit()

    attempt = Attempt(
        user_id=current_user.id,
        topic_id=default_topic.id,
        created_at=datetime.now(timezone.utc),
        finished_at=None,
        question_count=final_count,
        time_per_q=time_per_q
    )
    db.session.add(attempt)
    db.session.commit()

    for q in chosen_qs:
        db.session.add(AttemptAnswer(
            attempt_id=attempt.id,
            question_id=q.id,
            answered=False
        ))
    db.session.commit()

    return redirect(url_for("quiz_do", attempt_id=attempt.id))


@app.route("/quiz/<int:attempt_id>", methods=["GET", "POST"])
@login_required
def quiz_do(attempt_id):
    attempt = db.session.get(Attempt, attempt_id)
    if not attempt or attempt.user_id != current_user.id:
        return "Không hợp lệ", 403

    if attempt.finished_at:
        return redirect(url_for("quiz_result", attempt_id=attempt.id))

    unanswered = AttemptAnswer.query.filter_by(
        attempt_id=attempt.id,
        answered=False
    ).first()

    if not unanswered:
        attempt.finished_at = datetime.utcnow()
        db.session.commit()
        return redirect(url_for("quiz_result", attempt_id=attempt.id))

    q = db.session.get(Question, unanswered.question_id)
    if not q:
        return "Câu hỏi không tồn tại", 404

    correct_indexes = parse_correct_indexes(q)

    # ===================== POST =====================
    if request.method == "POST":

        # ===== MULTI =====
        if q.type == "multi":
            raw_ids = request.form.getlist("choice_ids[]")

            if not raw_ids:
                unanswered.answered = True
                unanswered.chosen_choice_id = None
                unanswered.chosen_choice_ids = json.dumps([])
                unanswered.is_correct = False
                db.session.commit()
                return redirect(url_for("quiz_do", attempt_id=attempt.id))

            chosen_indexes = []
            for x in raw_ids:
                x = str(x).strip()
                if x.isdigit():
                    chosen_indexes.append(int(x))

            chosen_indexes = sorted(set(chosen_indexes))

            valid_answer_indexes = {
                i for i, txt in enumerate(question_answer_texts(q), start=1)
                if (txt or "").strip()
            }

            if not chosen_indexes or any(i not in valid_answer_indexes for i in chosen_indexes):
                unanswered.answered = True
                unanswered.chosen_choice_id = None
                unanswered.chosen_choice_ids = json.dumps([])
                unanswered.is_correct = False
                db.session.commit()
                return redirect(url_for("quiz_do", attempt_id=attempt.id))

            unanswered.answered = True
            unanswered.chosen_choice_id = None
            unanswered.chosen_choice_ids = json.dumps(chosen_indexes)
            unanswered.is_correct = (set(chosen_indexes) == correct_indexes)

            db.session.commit()
            return redirect(url_for("quiz_do", attempt_id=attempt.id))

        # ===== MCQ / BOOLEAN =====
        chosen_id = request.form.get("choice_id")

        if not chosen_id or not str(chosen_id).strip().isdigit():
            unanswered.answered = True
            unanswered.chosen_choice_id = None
            unanswered.is_correct = False
            db.session.commit()
            return redirect(url_for("quiz_do", attempt_id=attempt.id))

        chosen_idx = int(chosen_id)

        valid_answer_indexes = {
            i for i, txt in enumerate(question_answer_texts(q), start=1)
            if (txt or "").strip()
        }

        if chosen_idx not in valid_answer_indexes:
            unanswered.answered = True
            unanswered.chosen_choice_id = None
            unanswered.is_correct = False
            db.session.commit()
            return redirect(url_for("quiz_do", attempt_id=attempt.id))

        unanswered.answered = True
        unanswered.chosen_choice_id = chosen_idx   # giờ lưu orig_idx thay vì choice.id
        unanswered.chosen_choice_ids = None
        unanswered.is_correct = (chosen_idx in correct_indexes)

        db.session.commit()
        return redirect(url_for("quiz_do", attempt_id=attempt.id))

    # ===================== GET =====================
    total = AttemptAnswer.query.filter_by(attempt_id=attempt.id).count()
    done = AttemptAnswer.query.filter_by(attempt_id=attempt.id, answered=True).count()

    # ===== GIỮ THỨ TỰ RANDOM CỐ ĐỊNH CHO TỪNG CÂU =====
    session_key = f"quiz_answer_order_{attempt.id}_{q.id}"
    forced_order = session.get(session_key)

    if not forced_order:
        base_answers = question_answers_payload(q, shuffle_answers=True)
        forced_order = [item["orig_idx"] for item in base_answers]
        session[session_key] = forced_order
        session.modified = True

    answers_payload = question_answers_payload(
        q,
        shuffle_answers=False,
        forced_order=forced_order
    )

    correct_count = len(correct_indexes) if q.type == "multi" else 0

    return render_template(
        "quiz.html",
        attempt=attempt,
        question=q,
        answers_payload=answers_payload,
        progress=(done, total),
        time_per_q=attempt.time_per_q,
        correct_count=correct_count
    )


@app.route("/quiz/<int:attempt_id>/result")
@login_required
def quiz_result(attempt_id):
    attempt = db.session.get(Attempt, attempt_id)
    if not attempt or attempt.user_id != current_user.id:
        return "Không hợp lệ", 403

    answers = AttemptAnswer.query.filter_by(attempt_id=attempt.id).all()
    score = sum(1 for a in answers if a.is_correct)
    total = len(answers)

    if (
        current_user.last_score != score
        or current_user.last_total != total
    ):
        current_user.last_score = score
        current_user.last_total = total
        current_user.play_count = (current_user.play_count or 0) + 1
        db.session.commit()

    review = []
    first_question = None

    for a in answers:
        q = db.session.get(Question, a.question_id)
        if not q:
            continue

        if not first_question:
            first_question = q

        correct_indexes = parse_correct_indexes(q)

        chosen_indexes = set()
        if a.chosen_choice_ids:
            try:
                chosen_indexes = set(int(x) for x in json.loads(a.chosen_choice_ids))
            except Exception:
                chosen_indexes = set()
        elif a.chosen_choice_id:
            chosen_indexes = {int(a.chosen_choice_id)}

        show_warning = not bool(chosen_indexes)

        choices_view = []
        payload = question_answers_payload(q, shuffle_answers=False)

        for item in payload:
            idx = item["orig_idx"]
            picked = idx in chosen_indexes
            correct = idx in correct_indexes

            if picked and correct:
                state = "correct"
            elif picked and not correct:
                state = "wrong"
            elif not picked and correct:
                state = "missed"
            else:
                state = "normal"

            choices_view.append({
                "label": item["label"],
                "text": item["text"],
                "state": state
            })

        review.append({
            "question": q,
            "choices": choices_view,
            "show_warning": show_warning,
            "is_correct": bool(a.is_correct),
            "result_text": "Chưa chọn" if show_warning else ("Đúng" if a.is_correct else "Sai")
        })

    folder3 = None
    if first_question:
        folder3 = db.session.get(Folder, first_question.folder_id)

    return render_template(
        "result.html",
        attempt=attempt,
        score=score,
        total=total,
        review=review,
        topic_name=folder3.name if folder3 else "Ôn tập",
        folder3_id=folder3.id if folder3 else None,
        replay_url=url_for(
            "quiz_start_folder",
            folder3_id=folder3.id
        ) if folder3 else url_for("main")
    )





@app.route("/admin/logs")
@login_required
def admin_logs():
    admin_required()

    logs = LoginLogSummary.query.order_by(LoginLogSummary.last_at.desc()).all()

    return render_template(
        "admin_logs.html",
        logs=logs
    )








@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def admin_users():
    admin_required()

    # ===============================
    # ✅ HELPER: status text cho UI
    # ===============================
    def status_text(user):
        st = (user.status or "").upper()

        if st == "LOCK":
            return "Khoá"
        if st == "WAIT_ACCEPT":
            return "Chờ duyệt"
        if st == "WAIT_RENEW":
            return "Chờ gia hạn"
        if st == "ACTIVE":
            if user.role == "user" and (not getattr(user, "email_verified", False)):
                return "Chờ kích hoạt"
            return "Hoạt động"

        return st or "Không rõ"

    # ===============================
    # ✅ HELPER: remaining days
    # ===============================
    def remaining_days(user):
        if not user.trial_end:
            return None
        end_date = user.trial_end.date() if hasattr(user.trial_end, "date") else user.trial_end
        today = datetime.now().date()
        d = (end_date - today).days
        return d if d > 0 else 0

    # =====================================================
    # POST
    # =====================================================
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()

        # =====================================================
        # ✅ 1) BULK ACTIONS
        # =====================================================
        if action in ("bulk_extend_trial", "bulk_lock", "bulk_unlock"):
            raw_ids = request.form.getlist("user_ids[]") or request.form.getlist("user_ids")
            user_ids = []
            for x in raw_ids:
                try:
                    user_ids.append(int(x))
                except:
                    pass

            if not user_ids:
                flash("❌ Bạn chưa chọn user nào.", "danger")
                return redirect(url_for("admin_users"))

            targets = (
                User.query
                .filter(User.id.in_(user_ids), User.is_deleted == False)
                .all()
            )

            # loại bỏ chính mình + loại bỏ admin
            filtered = []
            for u in targets:
                if u.id == current_user.id:
                    continue
                if u.role == "admin":
                    continue
                filtered.append(u)

            if not filtered:
                flash("❌ Không có user hợp lệ để thao tác (không thao tác admin / chính mình).", "danger")
                return redirect(url_for("admin_users"))

            # ---------- ✅ BULK LOCK (status=LOCK) ----------
            if action == "bulk_lock":
                locked = 0
                skipped = 0

                for u in filtered:
                    if (u.status or "").upper() == "LOCK":
                        skipped += 1
                        continue
                    u.status = "LOCK"
                    locked += 1

                db.session.commit()
                flash(f"✅ Đã khoá {locked} user. (Bỏ qua {skipped} user đã khoá sẵn)", "success")
                return redirect(url_for("admin_users"))

            # ---------- ✅ BULK UNLOCK (status=ACTIVE) ----------
            if action == "bulk_unlock":
                unlocked = 0
                skipped = 0

                for u in filtered:
                    if (u.status or "").upper() == "ACTIVE":
                        skipped += 1
                        continue
                    u.status = "ACTIVE"
                    unlocked += 1

                db.session.commit()
                flash(f"✅ Đã mở khoá {unlocked} user. (Bỏ qua {skipped} user đang ACTIVE)", "success")
                return redirect(url_for("admin_users"))

            # ---------- ✅ BULK EXTEND (gia hạn + status=ACTIVE) ----------
            if action == "bulk_extend_trial":
                days = request.form.get("days", type=int)
                if not days or days <= 0:
                    flash("❌ Số ngày gia hạn không hợp lệ.", "danger")
                    return redirect(url_for("admin_users"))

                now = to_naive_utc(datetime.now(timezone.utc))
                extended = 0
                mail_sent = 0
                mail_fail = 0

                now = _to_utc_aware(now_vn())

                for u in filtered:
                    if not u.trial_start:
                        u.trial_start = now_vn()

                    trial_end = _to_utc_aware(u.trial_end) if u.trial_end else None
                    base = trial_end if (trial_end and trial_end > now) else now

                    u.trial_end = base + timedelta(days=days)
                    u.status = "ACTIVE"
                    extended += 1

                db.session.commit()

                # gửi mail sau commit
                for u in filtered:
                    if not u.email:
                        continue
                    try:
                        subject = "Gia hạn thời gian sử dụng - Hệ thống học tập Taekwondo"
                        end_str = u.trial_end.strftime("%d/%m/%Y")

                        end_date = u.trial_end.date() if hasattr(u.trial_end, "date") else u.trial_end
                        remaining = (end_date - datetime.now().date()).days

                        html = render_template(
                            "base_email.html",
                            title="Gia hạn thời gian sử dụng",
                            preheader="Tài khoản của bạn đã được gia hạn.",
                            username=u.username,
                            current_year=datetime.now().year,

                            brand_name="Hệ thống học tập Taekwondo",
                            brand_url=BASE_URL,
                            logo_url=LOGO_URL,
                            header_right_text="",
                            brand_address="TP.HCM, Việt Nam",
                            support_email="silentnight1993pro@gmail.com",
                            unsubscribe_url=None,

                            message_html=f"""
                              <p style="margin:0 0 10px;">Xin chào, <strong>{u.username}</strong>!</p>
                              <p style="margin:0 0 12px;">Tài khoản của bạn đã được gia hạn thời gian sử dụng.</p>

                              <div style="
                                margin:14px 0 14px;
                                padding:12px 14px;
                                background:#f9fafb;
                                border:1px solid #e5e7eb;
                                border-radius:12px;
                                line-height:1.7;
                              ">
                                <div><strong>ID:</strong> {u.username}</div>
                                <div style="margin-top:6px;">
                                  <strong>Gia hạn đến:</strong>
                                  <span style="font-weight:800; color:#111827;">{end_str}</span>
                                </div>
                                <div style="margin-top:6px;">
                                  <strong>Còn lại:</strong>
                                  <span style="font-size:16px; font-weight:800; color:#1d4ed8;">{remaining} ngày</span>
                                </div>
                              </div>

                              <p style="margin:10px 0 0;">Xin cảm ơn!</p>
                            """,
                            button_text="Vào trang web",
                            button_url=get_base_url(),
                            note_html=None
                        )

                        send_email(u.email, subject, html)
                        mail_sent += 1
                    except Exception as e:
                        print("[EMAIL] bulk_extend send error:", e)
                        mail_fail += 1

                flash(f"✅ Đã gia hạn {extended} user. Email: gửi {mail_sent}, lỗi {mail_fail}.", "success")
                return redirect(url_for("admin_users"))

        # =====================================================
        # ✅ 2) SINGLE ACTIONS
        # =====================================================
        uid = request.form.get("user_id", type=int)

        if not uid or not action:
            flash("❌ Dữ liệu không hợp lệ.", "danger")
            return redirect(url_for("admin_users"))

        u = User.query.filter_by(id=uid, is_deleted=False).first_or_404()

        if u.id == current_user.id:
            flash("❌ Không thể thao tác với chính tài khoản đang đăng nhập.", "danger")
            return redirect(url_for("admin_users"))

        if action == "delete":
            if u.username == "nhoctotokute93":
                flash("❌ Không thể xoá tài khoản ADMIN hệ thống.", "danger")
                return redirect(url_for("admin_users"))

            if u.role == "admin":
                admin_count = User.query.filter_by(role="admin", is_deleted=False).count()
                if admin_count <= 1:
                    flash("❌ Không thể xoá admin cuối cùng.", "danger")
                    return redirect(url_for("admin_users"))

        # ✅ toggle khoá/mở bằng status
        if action == "toggle_active":
            st = (u.status or "").upper()
            u.status = "ACTIVE" if st == "LOCK" else "LOCK"
            db.session.commit()
            flash("🔒 Đã cập nhật trạng thái tài khoản.", "success")

        elif action == "toggle_role":
            u.role = "admin" if u.role == "user" else "user"
            db.session.commit()
            flash("🔁 Đã đổi role người dùng.", "success")

        elif action == "extend_trial":
            days = request.form.get("days", type=int)
            if not days or days <= 0:
                flash("❌ Số ngày gia hạn không hợp lệ.", "danger")
                return redirect(url_for("admin_users"))

            now = _to_utc_aware(now_vn())

            if not u.trial_start:
                u.trial_start = now_vn()

            trial_end = _to_utc_aware(u.trial_end) if u.trial_end else None
            base = trial_end if (trial_end and trial_end > now) else now

            u.trial_end = base + timedelta(days=days)

            # ✅ gia hạn xong -> ACTIVE
            u.status = "ACTIVE"

            db.session.commit()

            try:
                subject = "Gia hạn thời gian sử dụng - Hệ thống học tập Taekwondo"
                end_str = u.trial_end.strftime("%d/%m/%Y")
                end_date = u.trial_end.date() if hasattr(u.trial_end, "date") else u.trial_end
                remaining = (end_date - datetime.now().date()).days

                html = render_template(
                    "base_email.html",
                    title="Gia hạn thời gian sử dụng",
                    preheader="Tài khoản của bạn đã được gia hạn.",
                    username=u.username,
                    current_year=datetime.now().year,

                    brand_name="Hệ thống học tập Taekwondo",
                    brand_url=BASE_URL,
                    logo_url=LOGO_URL,
                    header_right_text="",
                    brand_address="TP.HCM, Việt Nam",
                    support_email="silentnight1993pro@gmail.com",
                    unsubscribe_url=None,

                    message_html=f"""
                      <p style="margin:0 0 10px;">Xin chào, <strong>{u.username}</strong>!</p>
                      <p style="margin:0 0 12px;">Tài khoản của bạn đã được gia hạn thời gian sử dụng.</p>

                      <div style="
                        margin:14px 0 14px;
                        padding:12px 14px;
                        background:#f9fafb;
                        border:1px solid #e5e7eb;
                        border-radius:12px;
                        line-height:1.7;
                      ">
                        <div><strong>ID:</strong> {u.username}</div>
                        <div style="margin-top:6px;">
                          <strong>Gia hạn đến:</strong>
                          <span style="font-weight:800; color:#111827;">{end_str}</span>
                        </div>
                        <div style="margin-top:6px;">
                          <strong>Còn lại:</strong>
                          <span style="font-size:16px; font-weight:800; color:#1d4ed8;">{remaining} ngày</span>
                        </div>
                      </div>

                      <p style="margin:10px 0 0;">Xin cảm ơn!</p>
                    """,
                    button_text="Vào trang web",
                    button_url=get_base_url(),
                    note_html=None
                )
                send_email(u.email, subject, html)
            except Exception as e:
                print("[EMAIL] extend_trial send error:", e)

            flash("✅ Đã gia hạn thành công!", "success")

        elif action == "delete":
            AccessAllow.query.filter_by(user_id=u.id).delete()

            try:
                Attempt.query.filter_by(user_id=u.id).delete()
            except:
                pass

            try:
                LoginLog.query.filter_by(username=u.username).delete()
            except:
                pass

            db.session.delete(u)
            db.session.commit()
            flash(f"🗑️ Đã xoá user {u.username}.", "success")

        return redirect(url_for("admin_users"))

    # =====================================================
    # GET
    # =====================================================
    admins = (
        User.query
        .filter_by(role="admin", is_deleted=False)
        .order_by(User.username.asc())
        .all()
    )

    status_rank = case(
        (User.status == "ACTIVE", 4),
        (User.status == "WAIT_ACCEPT", 3),
        (User.status == "WAIT_RENEW", 2),
        (User.status == "LOCK", 1),
        else_=0
    ).desc()

    score_ratio = (User.last_score * 1.0 / db.func.nullif(User.last_total, 0))

    users = (
        User.query
        .filter(User.role == "user", User.is_deleted == False)
        .order_by(
            status_rank,
            score_ratio.desc(),
            User.play_count.asc(),
            User.created_at.desc()
        )
        .all()
    )

    now = _to_utc_aware(now_vn())

    for uu in users:
        uu._remain_seconds = None
        uu._remain_days = None
        uu._remain_label = "-"

        if uu.role == "user" and uu.trial_end:
            trial_end = _to_utc_aware(uu.trial_end)
            remain_seconds = (trial_end - now).total_seconds()

            uu._remain_seconds = remain_seconds
            uu._remain_days = int(remain_seconds // 86400)

            if remain_seconds <= 0:
                uu._remain_label = "Hết hạn"
            elif remain_seconds < 3600:
                minutes = max(1, int(remain_seconds // 60))
                uu._remain_label = f"{minutes} phút"
            elif remain_seconds < 86400:
                hours = max(1, int(remain_seconds // 3600))
                uu._remain_label = f"{hours} giờ"
            else:
                uu._remain_label = f"{uu._remain_days} ngày"
    return render_template(
        "admin_users.html",
        admins=admins,
        users=users
    )



def calc_remain(trial_end):
    """
    Trả về dict:
      - label: "7 ngày" hoặc "34 giờ" hoặc "-" / "0 giờ"
      - kind:  "days" | "hours" | "none"
      - days:  int days floor (nếu kind=days)
      - hours: int hours floor (nếu kind=hours)
    Rule:
      - >= 72 giờ => hiển thị ngày (floor theo ngày)
      - < 72 giờ  => hiển thị giờ (floor theo giờ, bỏ phút)
    """
    if not trial_end:
        return {"label": "-", "kind": "none", "days": None, "hours": None}

    now = datetime.now(timezone.utc)

    # trial_end naive -> gắn UTC
    if getattr(trial_end, "tzinfo", None) is None:
        trial_end = trial_end.replace(tzinfo=timezone.utc)

    delta = trial_end - now
    total_seconds = delta.total_seconds()

    if total_seconds <= 0:
        return {"label": "0 giờ", "kind": "hours", "days": 0, "hours": 0}

    total_hours = total_seconds / 3600.0

    # >= 72 giờ => ngày
    if total_hours > 72:
        days = int(total_hours // 24)   # floor theo ngày
        return {"label": f"{days} ngày", "kind": "days", "days": days, "hours": None}

    # < 72 giờ => giờ (floor)
    hours = int(total_hours // 1)
    return {"label": f"{hours} giờ", "kind": "hours", "days": None, "hours": hours}


def remain_color_class(remain):
    """
    Màu theo yêu cầu Ken:
      >10 ngày  : xanh
      10-7 ngày : vàng
      6-4 ngày  : cam
      <3 ngày   : giờ + đỏ (đang label giờ rồi)
    """
    if not remain or remain.get("kind") == "none":
        return "remain-gray"

    if remain["kind"] == "hours":
        return "remain-red"

    d = remain.get("days")
    if d is None:
        return "remain-gray"

    if d > 10:
        return "remain-green"
    if 7 <= d <= 10:
        return "remain-yellow"
    if 4 <= d <= 6:
        return "remain-orange"
    return "remain-red"   # <=3 ngày => đỏ

@app.context_processor
def inject_trial_remain_days():
    """
    Gửi cho menu (chỉ user):
      - trial_remain_label : "7 ngày" / "34 giờ" / "-"
      - trial_remain_class : remain-green/yellow/orange/red/gray
    """
    label = "-"
    css_class = "remain-gray"

    try:
        if current_user.is_authenticated and getattr(current_user, "role", None) == "user":
            end_dt = getattr(current_user, "trial_end", None)
            remain = calc_remain(end_dt)

            label = remain["label"]
            css_class = remain_color_class(remain)

    except Exception as e:
        print("[CTX] inject_trial_remain_days error:", e)

    return dict(
        trial_remain_label=label,
        trial_remain_class=css_class
    )


@app.route("/admin/folder/add", methods=["POST"])
@login_required
def admin_folder_add():
    admin_required()


    name = (request.form.get("name") or "").strip()
    level = request.form.get("level", type=int)
    parent_id = request.form.get("parent_id", type=int)

    folder1_id = request.form.get("folder1_id", type=int)
    folder2_id = request.form.get("folder2_id", type=int)

    if not name or level not in (1, 2, 3):
        flash("Thiếu dữ liệu folder.", "danger")
        return redirect(url_for("admin_questions", folder1_id=folder1_id, folder2_id=folder2_id))

    if level == 1:
        parent_id = None
    elif not parent_id:
        flash("Thiếu folder cha.", "danger")
        return redirect(url_for("admin_questions", folder1_id=folder1_id, folder2_id=folder2_id))

    max_order = (
        db.session.query(db.func.max(Folder.order_index))
        .filter_by(level=level, parent_id=parent_id)
        .scalar()
    ) or 0

    f = Folder(
        name=name,
        level=level,
        parent_id=parent_id,
        order_index=max_order + 1,
        image=None
    )
    db.session.add(f)
    db.session.commit()

    # 🔥 ĐÚNG KEY: "image"
    image = request.files.get("image")
    if image and image.filename:
        f.image = save_folder_image(image, f.level, f.name)
        db.session.commit()

    flash("✅ Đã thêm.", "success")

    if level == 1:
        return redirect(url_for("admin_questions", folder1_id=f.id))
    if level == 2:
        return redirect(url_for("admin_questions", folder1_id=parent_id, folder2_id=f.id))
    return redirect(url_for("admin_questions",
                            folder1_id=folder1_id,
                            folder2_id=parent_id,
                            folder3_id=f.id))



def save_folder_image(file, level, name):
    

    folder = f"uploads/folder{level}"
    abs_folder = os.path.join(app.static_folder, folder)
    os.makedirs(abs_folder, exist_ok=True)

    final_name = f"{slugify(name)}.jpg"
    final_path = os.path.join(abs_folder, final_name)

    # 🔥 FILE TẠM (TRÁNH GHI ĐÈ)
    tmp_name = f"__tmp_{uuid4().hex}.jpg"
    tmp_path = os.path.join(abs_folder, tmp_name)

    file.stream.seek(0)
    img = Image.open(file)
    img = img.convert("RGB")

    w, h = img.size
    side = min(w, h)
    left = (w - side) // 2
    top  = (h - side) // 2

    img = img.crop((left, top, left + side, top + side))
    img = img.resize((320, 320), Image.LANCZOS)

    # ✅ LƯU FILE TẠM TRƯỚC
    img.save(tmp_path, "JPEG", quality=88, optimize=True)
    img.close()

    # ✅ XOÁ FILE CŨ SAU KHI LƯU OK
    if os.path.exists(final_path):
        os.remove(final_path)

    # ✅ ĐỔI TÊN FILE
    os.rename(tmp_path, final_path)

    return f"{folder}/{final_name}"


def save_lesson_image(file, lesson_title):
    

    # ✅ chỉ cho phép ảnh
    ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".webp"}
    filename = (getattr(file, "filename", "") or "").strip()
    ext = os.path.splitext(filename)[1].lower()
    mimetype = (getattr(file, "mimetype", "") or "").lower()

    if ext not in ALLOWED_EXTS and not mimetype.startswith("image/"):
        return None

    folder = os.path.join(current_app.static_folder, "uploads", "lessons")
    os.makedirs(folder, exist_ok=True)

    # ✅ tên file theo tên bài học Ken đặt
    base = vn_filename(lesson_title) or "lesson"
    final_name = f"{base}.jpg"
    final_path = os.path.join(folder, final_name)

    # ===== FILE TẠM =====
    tmp_name = f"__tmp_{uuid4().hex}.jpg"
    tmp_path = os.path.join(folder, tmp_name)

    try:
        file.stream.seek(0)
        img = Image.open(file).convert("RGB")

        # crop vuông
        w, h = img.size
        side = min(w, h)
        left = (w - side) // 2
        top  = (h - side) // 2
        img = img.crop((left, top, left + side, top + side))

        # resize
        img = img.resize((320, 320), Image.LANCZOS)

        img.save(tmp_path, "JPEG", quality=88, optimize=True)
        img.close()

        # ===== THAY THẾ FILE CHÍNH (overwrite an toàn hơn) =====
        os.replace(tmp_path, final_path)
        return f"uploads/lessons/{final_name}"

    except PermissionError:
        # ✅ file đang bị lock (WinError 32) -> fallback để không crash
        fallback_name = f"{base}_{int(time.time())}.jpg"
        fallback_path = os.path.join(folder, fallback_name)
        try:
            os.replace(tmp_path, fallback_path)
            return f"uploads/lessons/{fallback_name}"
        except Exception:
            if os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except: pass
            return None

    except UnidentifiedImageError:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except: pass
        return None

    except Exception:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except: pass
        return None



def save_lesson_pdf(file, slug):

    folder = os.path.join(current_app.static_folder, "uploads", "lesson_pdfs")
    os.makedirs(folder, exist_ok=True)

    final_name = f"{slug}.pdf"
    final_path = os.path.join(folder, final_name)

    tmp_name = f"__tmp_{uuid4().hex}.pdf"
    tmp_path = os.path.join(folder, tmp_name)

    file.stream.seek(0)
    with open(tmp_path, "wb") as f:
        f.write(file.read())

    if os.path.exists(final_path):
        os.remove(final_path)

    os.rename(tmp_path, final_path)

    # path tương đối để url_for('static', filename=...)
    return f"uploads/lesson_pdfs/{final_name}"

import shutil
import fitz  # pymupdf


def get_lesson_pages_dir(slug):
    folder = os.path.join(current_app.static_folder, "uploads", "lesson_pages", slug)
    os.makedirs(folder, exist_ok=True)
    return folder


def clear_lesson_pages(slug):
    folder = os.path.join(current_app.static_folder, "uploads", "lesson_pages", slug)
    if os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)
    os.makedirs(folder, exist_ok=True)
    return folder


def convert_lesson_pdf_to_png(pdf_rel_path, slug, zoom=2.0):
    """
    pdf_rel_path: ví dụ uploads/lesson_pdfs/moa_seogi_tan_nghiem.pdf
    output: static/uploads/lesson_pages/<slug>/page_1.png ...
    """
    if not pdf_rel_path:
        return []

    pdf_abs_path = os.path.join(current_app.static_folder, pdf_rel_path)
    if not os.path.isfile(pdf_abs_path):
        return []

    out_dir = clear_lesson_pages(slug)
    saved = []

    doc = fitz.open(pdf_abs_path)
    try:
        matrix = fitz.Matrix(zoom, zoom)

        for i, page in enumerate(doc, start=1):
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            out_name = f"page_{i}.png"
            out_abs = os.path.join(out_dir, out_name)
            pix.save(out_abs)
            saved.append(f"uploads/lesson_pages/{slug}/{out_name}")
    finally:
        doc.close()

    return saved


def get_lesson_image_pages(slug):
    folder = os.path.join(current_app.static_folder, "uploads", "lesson_pages", slug)
    if not os.path.isdir(folder):
        return []

    exts = (".webp", ".png", ".jpg", ".jpeg")

    def sort_key(name):
        m = re.search(r"page_(\d+)", name.lower())
        return int(m.group(1)) if m else 999999

    files = sorted(
        [f for f in os.listdir(folder) if f.lower().endswith(exts)],
        key=sort_key
    )

    return [
        url_for("static", filename=f"uploads/lesson_pages/{slug}/{f}")
        for f in files
    ]

@app.route("/admin/folder/<int:folder_id>/edit", methods=["POST"])
@login_required
def admin_folder_edit(folder_id):
    admin_required()

    f = Folder.query.get_or_404(folder_id)

    old_image = f.image
    old_name  = f.name

    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Tên không được trống.", "danger")
        return redirect(request.referrer)

    f.name = name

    image = request.files.get("image")

    if image and image.filename:
        image.stream.seek(0)

        new_image = save_folder_image(image, f.level, name)

        if new_image:
            # xoá ảnh cũ nếu tên khác
            if old_image and old_image != new_image:
                old_path = os.path.join(app.static_folder, old_image)
                if os.path.exists(old_path):
                    os.remove(old_path)

            f.image = new_image

    db.session.commit()
    flash("✅ Đã cập nhật.", "success")
    return redirect(request.referrer)








# ================= API LOAD FOLDER (CHO DUPLICATE) =================

@app.route("/api/folder2/<int:folder1_id>")
@login_required
def api_folder2(folder1_id):
    folders = (
        Folder.query
        .filter_by(level=2, parent_id=folder1_id)
        .order_by(Folder.order_index.asc())
        .all()
    )

    return jsonify([
        {"id": f.id, "name": f.name}
        for f in folders
    ])


@app.route("/api/folder3/<int:folder2_id>")
@login_required
def api_folder3(folder2_id):
    folders = (
        Folder.query
        .filter_by(level=3, parent_id=folder2_id)
        .order_by(Folder.order_index.asc())
        .all()
    )

    return jsonify([
        {"id": f.id, "name": f.name}
        for f in folders
    ])



@app.route("/admin/folder/<int:folder_id>/delete", methods=["POST"])
@login_required
def admin_folder_delete(folder_id):
    admin_required()

    f = Folder.query.get_or_404(folder_id)

    # 🚫 chặn xoá nếu còn folder con
    if f.children and len(f.children) > 0:
        flash("❌ Folder còn thư mục con, xoá con trước.", "danger")
        return redirect(request.referrer or url_for("admin_questions"))

    # 🚫 nếu cấp 3: chặn xoá nếu còn câu hỏi
    if f.level == 3:
        qcount = Question.query.filter_by(folder_id=f.id).count()
        if qcount > 0:
            flash(f"❌ Folder còn {qcount} câu hỏi, xoá câu hỏi trước.", "danger")
            return redirect(request.referrer or url_for("admin_questions"))

    # =========================
    # 🗑️ XOÁ ẢNH CỦA FOLDER BỊ XOÁ
    # =========================
    if f.image:
        image_path = os.path.join(app.static_folder, f.image)
        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except Exception as e:
                print("⚠️ Không xoá được ảnh:", e)

    # lưu lại thông tin để đôn số
    deleted_order = f.order_index
    level = f.level
    parent_id = f.parent_id

    # =========================
    # 🗑️ XOÁ FOLDER TRONG DB
    # =========================
    db.session.delete(f)
    db.session.commit()

    # =========================
    # 🔁 ĐÔN order_index + ĐỔI TÊN ẢNH
    # =========================
    siblings = (
        Folder.query
        .filter(
            Folder.level == level,
            Folder.parent_id == parent_id,
            Folder.order_index > deleted_order
        )
        .order_by(Folder.order_index.asc())
        .all()
    )

    for s in siblings:
        old_index = s.order_index
        new_index = old_index - 1

        # nếu có ảnh → đổi tên ảnh
        if s.image:
            old_path = os.path.join(app.static_folder, s.image)
            ext = os.path.splitext(old_path)[1]
            new_filename = f"f{level}_{new_index}{ext}"
            new_rel_path = f"uploads/folder{level}/{new_filename}"
            new_path = os.path.join(app.static_folder, new_rel_path)

            if os.path.exists(old_path):
                try:
                    os.rename(old_path, new_path)
                    s.image = new_rel_path
                except Exception as e:
                    print("⚠️ Không đổi tên ảnh:", e)

        s.order_index = new_index

    db.session.commit()

    flash("✅ Đã xoá và tự động sắp xếp lại.", "success")
    return redirect(url_for("admin_questions"))


# ===================== API: GET QUESTION =====================
@app.route("/api/question/<int:qid>")
@login_required
def api_question(qid):
    q = db.session.get(Question, qid)
    if not q:
        return jsonify(ok=False)

    answers = question_answers_payload(q, shuffle_answers=False)
    correct_indexes = parse_correct_indexes(q)

    return jsonify(
        ok=True,
        id=q.id,
        text=q.text,
        type=q.type,
        answers=[
            {
                "orig_idx": a["orig_idx"],
                "label": a["label"],
                "text": a["text"],
                "is_correct": a["orig_idx"] in correct_indexes
            }
            for a in answers
        ],
        answer_count=q.answer_count or 0,
        correct_indexes=sorted(list(correct_indexes)),
        correct_answers_text=q.correct_answers_text or ""
    )







@app.route("/admin/questions", methods=["GET", "POST"])
@login_required
def admin_questions():
    admin_required()

    # ================= POST: ADD QUESTION =================
    if request.method == "POST":
        question_text = request.form.get("question_text", "").strip()
        question_type = request.form.get("question_type", "mcq")
        folder_id = request.form.get("folder3_id", type=int)

        if not folder_id or not question_text:
            return jsonify({"error": "Thiếu thông tin câu hỏi"}), 400

        q = Question(
            text=question_text,
            folder_id=folder_id,
            type=question_type,
            member_plans="FREE,BASIC,PRO,VIP"
        )
        db.session.add(q)
        db.session.flush()

        # ===== MCQ =====
        if question_type == "mcq":
            ans_a = request.form.get("answer_a", "").strip()
            ans_b = request.form.get("answer_b", "").strip()
            ans_c = request.form.get("answer_c", "").strip()
            ans_d = request.form.get("answer_d", "").strip()
            correct = (request.form.get("correct_answer") or "").strip().upper()

            if not all([ans_a, ans_b, ans_c, ans_d]):
                return jsonify({"error": "Vui lòng nhập đủ 4 đáp án"}), 400
            if correct not in ("A", "B", "C", "D"):
                return jsonify({"error": "Chưa chọn đáp án đúng"}), 400

            answers = [ans_a, ans_b, ans_c, ans_d]
            correct_indexes = [{"A": 1, "B": 2, "C": 3, "D": 4}[correct]]
            fill_question_answers(q, answers, correct_indexes)

        # ===== BOOLEAN =====
        elif question_type == "boolean":
            correct = (request.form.get("correct_answer") or "").strip().upper()
            if correct not in ("A", "B"):
                return jsonify({"error": "Chưa chọn đáp án đúng"}), 400

            answers = ["Đúng", "Sai"]
            correct_indexes = [1 if correct == "A" else 2]
            fill_question_answers(q, answers, correct_indexes)

        # ===== MULTI =====
        elif question_type == "multi":
            texts = request.form.getlist("multi_text[]")[:12]
            corrects = request.form.getlist("multi_correct[]")[:12]

            pairs = []
            for text, flag in zip(texts, corrects):
                text = (text or "").strip()
                if text:
                    pairs.append((text, str(flag).strip() == "1"))

            if len(pairs) > 12:
                return jsonify({"error": "Multi chỉ được tối đa 12 đáp án"}), 400

            correct_indexes = [i for i, (_, ok) in enumerate(pairs, start=1) if ok]
            if not correct_indexes:
                return jsonify({"error": "Cần chọn ít nhất 1 đáp án đúng"}), 400

            answers = [txt for txt, _ in pairs]
            fill_question_answers(q, answers, correct_indexes)

        else:
            return jsonify({"error": "Kiểu câu hỏi không hợp lệ"}), 400


        # 🔥 BẮT BUỘC PHẢI CÓ
        db.session.commit()
        return jsonify({"success": True})

    # ================= GET: LOAD PAGE =================
    folder1_id = request.args.get("folder1_id", type=int)
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    folder1_list = Folder.query.filter_by(level=1)\
        .order_by(Folder.order_index.asc()).all()

    if folder1_id and not any(f.id == folder1_id for f in folder1_list):
        folder1_id = folder1_list[0].id if folder1_list else None
    elif not folder1_id and folder1_list:
        folder1_id = folder1_list[0].id


    folder2_list = Folder.query.filter_by(
        level=2, parent_id=folder1_id
    ).order_by(Folder.order_index.asc()).all()

    if folder2_id and not any(f.id == folder2_id for f in folder2_list):
        folder2_id = folder2_list[0].id if folder2_list else None
    elif not folder2_id and folder2_list:
        folder2_id = folder2_list[0].id


    folder3_list = Folder.query.filter_by(
        level=3, parent_id=folder2_id
    ).order_by(Folder.order_index.asc()).all()

    if folder3_id and not any(f.id == folder3_id for f in folder3_list):
        folder3_id = folder3_list[0].id if folder3_list else None
    elif not folder3_id and folder3_list:
        folder3_id = folder3_list[0].id


    selected_folder1 = db.session.get(Folder, folder1_id) if folder1_id else None
    selected_folder2 = db.session.get(Folder, folder2_id) if folder2_id else None
    selected_folder3 = db.session.get(Folder, folder3_id) if folder3_id else None
    
    # ===== LOAD QUESTIONS =====
    questions = (
        Question.query
            .filter_by(folder_id=folder3_id)
            .order_by(Question.id.desc())
            .all()
        if folder3_id else []
    )

    # ===============================
    # 🔥 THỐNG KÊ ĐÁP ÁN ĐÚNG (DYNAMIC – ALL TYPES)
    # ===============================
    answer_stats = {}
    total_correct = 0

    if folder3_id:
        all_questions = Question.query.filter_by(folder_id=folder3_id).all()

        for q in all_questions:
            correct_indexes = parse_correct_indexes(q)
            for idx in sorted(correct_indexes):
                letter = chr(64 + idx) if 1 <= idx <= 26 else f"#{idx}"
                answer_stats[letter] = answer_stats.get(letter, 0) + 1
                total_correct += 1


    # ⬇️ RỒI TỚI ĐÂY
    return render_template(
        "admin_questions.html",
        folder1_list=folder1_list,
        folder2_list=folder2_list,
        folder3_list=folder3_list,
        selected_folder1=selected_folder1,
        selected_folder2=selected_folder2,
        selected_folder3=selected_folder3,
        questions=questions,
        answer_stats=answer_stats,
        total_correct=total_correct,
    )


@app.route("/admin/question/<int:question_id>/edit", methods=["POST"])
@login_required
def admin_edit_question(question_id):
    admin_required()

    q = db.session.get(Question, question_id)
    if not q:
        return jsonify({"error": "Không tìm thấy câu hỏi"}), 404

    q.text = request.form.get("question_text", "").strip()
    if not q.text:
        return jsonify({"error": "Thiếu nội dung"}), 400

    qtype = (q.type or "").lower().strip()

    if qtype == "mcq":
        ans_a = request.form.get("answer_a", "").strip()
        ans_b = request.form.get("answer_b", "").strip()
        ans_c = request.form.get("answer_c", "").strip()
        ans_d = request.form.get("answer_d", "").strip()
        correct = (request.form.get("correct_answer") or "").strip().upper()

        if not all([ans_a, ans_b, ans_c, ans_d]):
            return jsonify({"error": "Thiếu đáp án"}), 400
        if correct not in ["A", "B", "C", "D"]:
            return jsonify({"error": "Chưa chọn đáp án đúng"}), 400

        answers = [ans_a, ans_b, ans_c, ans_d]
        correct_indexes = [{"A": 1, "B": 2, "C": 3, "D": 4}[correct]]
        fill_question_answers(q, answers, correct_indexes)

    elif qtype == "boolean":
        correct = (request.form.get("correct_answer") or "").strip().upper()
        if correct not in ["A", "B"]:
            return jsonify({"error": "Thiếu đáp án đúng"}), 400

        answers = ["Đúng", "Sai"]
        correct_indexes = [1 if correct == "A" else 2]
        fill_question_answers(q, answers, correct_indexes)

    elif qtype == "multi":
        texts = request.form.getlist("multi_text[]")
        corrects = request.form.getlist("multi_correct[]")

        pairs = []
        for text, flag in zip(texts, corrects):
            text = (text or "").strip()
            if text:
                pairs.append((text, str(flag).strip() == "1"))

        if len(pairs) < 2:
            return jsonify({"error": "Multi cần ít nhất 2 đáp án"}), 400

        correct_indexes = [i for i, (_, ok) in enumerate(pairs, start=1) if ok]
        if not correct_indexes:
            return jsonify({"error": "Cần chọn ít nhất 1 đáp án đúng"}), 400

        answers = [txt for txt, _ in pairs]
        fill_question_answers(q, answers, correct_indexes)

    else:
        return jsonify({"error": f"Kiểu câu hỏi không hỗ trợ: {q.type}"}), 400

    db.session.commit()
    return jsonify({"success": True})



# ===================== ADMIN: DELETE QUESTION (AJAX) =====================
@app.post("/admin/questions/<int:question_id>/delete")
@login_required
def admin_delete_question(question_id):
    admin_required()

    try:
        q = db.session.get(Question, question_id)
        if not q:
            return jsonify({"ok": False, "message": "Không tìm thấy câu hỏi"}), 404

        f3 = q.folder
        f2 = f3.parent if f3 else None
        f1 = f2.parent if f2 else None

        folder1_id = f1.id if f1 else None
        folder2_id = f2.id if f2 else None
        folder3_id = f3.id if f3 else None

        # Xóa các attempt answers đang tham chiếu câu này
        AttemptAnswer.query.filter_by(question_id=question_id).delete()

        db.session.delete(q)
        db.session.commit()

        return jsonify({
            "ok": True,
            "message": "Đã xóa câu hỏi",
            "redirect": url_for(
                "admin_questions",
                folder1_id=folder1_id,
                folder2_id=folder2_id,
                folder3_id=folder3_id
            )
        })

    except Exception as e:
        db.session.rollback()
        print("admin_delete_question error:", e)
        return jsonify({"ok": False, "message": f"Lỗi xóa câu hỏi: {e}"}), 500



@app.route("/admin/question/duplicate", methods=["POST"])
@login_required
def duplicate_question():
    admin_required()

    qid = request.form.get("question_id", type=int)
    folder3_id = request.form.get("folder3_id", type=int)

    if not qid or not folder3_id:
        flash("❌ Thiếu dữ liệu để nhân câu hỏi.", "error")
        return redirect(url_for("admin_questions"))

    old_q = db.session.get(Question, qid)
    if not old_q:
        flash("❌ Không tìm thấy câu hỏi gốc.", "error")
        return redirect(url_for("admin_questions"))

    new_q = Question(
        text=old_q.text,
        type=old_q.type,
        folder_id=folder3_id,
        member_plans=old_q.member_plans or "FREE,BASIC,PRO,VIP",

        answer_1=old_q.answer_1,
        answer_2=old_q.answer_2,
        answer_3=old_q.answer_3,
        answer_4=old_q.answer_4,
        answer_5=old_q.answer_5,
        answer_6=old_q.answer_6,
        answer_7=old_q.answer_7,
        answer_8=old_q.answer_8,
        answer_9=old_q.answer_9,
        answer_10=old_q.answer_10,
        answer_11=old_q.answer_11,
        answer_12=old_q.answer_12,
        answer_count=old_q.answer_count,
        correct_indexes=old_q.correct_indexes,
        correct_answers_text=old_q.correct_answers_text
    )
    db.session.add(new_q)
    db.session.commit()

    flash(f"🔁 Đã nhân câu hỏi #{old_q.id} → #{new_q.id}", "success")

    f3 = Folder.query.get(folder3_id)
    return redirect(url_for(
        "admin_questions",
        folder1_id=f3.parent.parent_id if f3 and f3.parent else None,
        folder2_id=f3.parent_id if f3 else None,
        folder3_id=folder3_id
    ))



@app.route("/api/question/<int:qid>/path")
@login_required
def api_question_path(qid):
    q = db.session.get(Question, qid)
    if not q or not q.folder:
        return jsonify(ok=False)

    f3 = q.folder
    f2 = f3.parent
    f1 = f2.parent

    return jsonify(
        ok=True,
        folder1_id=f1.id,
        folder2_id=f2.id,
        folder3_id=f3.id
    )




DEFAULT_NUM_QUESTIONS = 10
DEFAULT_TIME_PER_Q = 30

NUMQ_OPTIONS = [10, 15, 20, 30, 45, 60]   # dropdown
TIME_OPTIONS = [5, 10, 15, 20, 30, 45, 60, 90]  # dropdown


@app.route("/settings", methods=["GET"])
@login_required
def settings():
    cur_num = current_user.pref_num_questions
    cur_time = current_user.pref_time_per_q

    # ❗ GIỮ NGUYÊN None
    cur_num_display = cur_num        # có thể là None
    cur_time_display = cur_time      # có thể là None

    return render_template(
        "settings.html",
        NUMQ_OPTIONS=NUMQ_OPTIONS,
        TIME_OPTIONS=TIME_OPTIONS,
        cur_num=cur_num_display,
        cur_time=cur_time_display
    )





@app.route("/settings/save", methods=["POST"])
@login_required
def save_settings():
    num_questions = request.form.get("num_questions")
    time_per_q = request.form.get("time_per_q")

    # xử lý lưu DB ở đây
    current_user.pref_num_questions = (
        None if num_questions == "none" else int(num_questions)
    )
    current_user.pref_time_per_q = (
        None if time_per_q == "none" else int(time_per_q)
    )
    db.session.commit()

    # ✅ FLASH
    flash("Đã lưu cài đặt ôn tập", "success")

    # ✅ BẮT BUỘC redirect
    return redirect(url_for("settings"))







def seed_admin():
    ADMIN_USER = "nhoctotokute93"
    ADMIN_PASS = "Nguyenthienphung#93"

    u = User.query.filter_by(username=ADMIN_USER).first()
    if u:
        if u.role != "admin":
            u.role = "admin"
            db.session.commit()
        return

    u = User(
        username=ADMIN_USER,
        pw_hash=generate_password_hash(ADMIN_PASS),
        role="admin"
    )
    db.session.add(u)
    db.session.commit()
    print("✅ Đã tạo tài khoản ADMIN mặc định.")


TRIAL_DAYS_DEFAULT = 7

def send_activation_email(user):
    token = secrets.token_urlsafe(32)

    user.activation_token = token
    user.activation_sent_at = datetime.utcnow()
    db.session.commit()

    activate_url = url_for("activate_account", token=token, _external=True)
    website_url = get_base_url()

    html = render_template(
        "base_email.html",
        title="Kích Hoạt Tài Khoản",
        preheader="Vui lòng kích hoạt tài khoản để bắt đầu dùng thử.",
        username=user.username,
        current_year=datetime.now().year,
        brand_name="Hệ thống học tập Taekwondo",
        brand_url=BASE_URL,
        logo_url=LOGO_URL,
        header_right_text="",
        brand_address="TP.HCM, Việt Nam",
        support_email="silentnight1993pro@gmail.com",
        unsubscribe_url=None,
        message_html=f"""
          <p style="margin:0 0 10px;">Xin chào, <strong>{user.username}</strong>!</p>

          <p style="margin:0 0 12px;">
            Xin cảm ơn bạn đã tin tưởng và sử dụng hệ thống học tập Taekwondo.
          </p>

          <p style="margin:0 0 12px;">
            Để tài khoản hoạt động, xin vui lòng bấm nút <strong>Kích hoạt tài khoản</strong> bên dưới để bắt đầu dùng thử
            <strong>Hệ thống học tập Taekwondo</strong>.
          </p>

          <p style="margin:0 0 12px;">
            <strong>Thời gian dùng thử là: {TRIAL_DAYS_DEFAULT} ngày</strong>
          </p>

          <p style="margin:10px 0 0;">
            Chúc các bạn có những buổi học và ôn tập thật thú vị.
          </p>
          <p style="margin:10px 0 0;">Xin cảm ơn!</p>
        """,
        button_text="Kích hoạt tài khoản",
        button_url=activate_url,
        note_html=f"""
          <div style="margin-top:14px;">
            <a href="{website_url}" style="
              display:inline-block;
              padding:10px 14px;
              border-radius:10px;
              background:#0ea5e9;
              color:#fff;
              text-decoration:none;
              font-weight:700;
            ">Vào trang web</a>
          </div>
          <div style="margin-top:10px; font-size:13px; color:#64748b;">
            Nếu nút kích hoạt không bấm được, copy link này:
            <span style="word-break:break-all;">{activate_url}</span>
          </div>
        """
    )

    return send_email(user.email, "Kích hoạt tài khoản – Hệ thống học tập Taekwondo", html)





def send_email(to_email, subject, html_body):
    api_key = (os.getenv("RESEND_API_KEY") or "").strip()
    mail_from = (os.getenv("MAIL_FROM") or "Phungtkdsystem <no-reply@phungtkdsystem.online>").strip()

    print("[MAIL] RESEND key len =", len(api_key))
    print("[MAIL] from =", mail_from)
    print("[MAIL] to =", to_email, " subject =", subject)

    if not api_key:
        print("[EMAIL] Missing RESEND_API_KEY -> skip sending")
        return False

    try:
        resend.api_key = api_key

        params = {
            "from": mail_from,
            "to": [to_email],
            "subject": subject,
            "html": html_body or "",
        }

        result = resend.Emails.send(params)
        print("[EMAIL] Sent OK ->", to_email, result)
        return True

    except Exception as e:
        print("[EMAIL] Send failed:", e)
        return False


def create_notification(role, title, message="", target_url=None, user_id=None, icon="🔔",
                        action_type=None, ref_user_id=None, ref_plan_code=None, ref_months=None):
    n = Notification(
        role=role,
        user_id=user_id,
        title=title,
        message=message or "",
        target_url=target_url,
        icon=icon or "🔔",
        is_read=False,
        action_type=action_type,
        ref_user_id=ref_user_id,
        ref_plan_code=ref_plan_code,
        ref_months=ref_months,
        is_done=False,
        created_at=now_vn()
    )
    db.session.add(n)
    db.session.commit()
    return n



@app.route("/admin/educations", methods=["GET"])
@login_required
def admin_educations():
    admin_required()

    # ======================================================
    # 🔥 GET PARAMS (int/None)
    # ======================================================
    folder1_id = request.args.get("folder1_id", type=int)
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    # ===============================
    # CẤP 1
    # ===============================
    folder1_list = (
        EduFolder.query
        .filter_by(level=1, parent_id=None)   # ✅ sạch data bẩn
        .order_by(EduFolder.order.asc(), EduFolder.id.asc())
        .all()
    )

    if not folder1_list:
        return render_template(
            "admin_educations.html",
            folder1_list=[],
            folder2_list=[],
            folder3_list=[],
            selected_folder1=None,
            selected_folder2=None,
            selected_folder3=None,
            lessons=[]
        )

    # Nếu chưa chọn → lấy cái đầu tiên
    if not folder1_id:
        folder1_id = folder1_list[0].id

    selected_folder1 = db.session.get(EduFolder, folder1_id)
    if not selected_folder1 or selected_folder1.level != 1:
        selected_folder1 = folder1_list[0]
        folder1_id = selected_folder1.id
        folder2_id = None
        folder3_id = None

    # ===============================
    # CẤP 2
    # ===============================
    folder2_list = []
    selected_folder2 = None

    if selected_folder1:
        folder2_list = (
            EduFolder.query
            .filter_by(level=2, parent_id=selected_folder1.id)
            .order_by(EduFolder.order.asc(), EduFolder.id.asc())
            .all()
        )

        if folder2_list:
            if not folder2_id:
                folder2_id = folder2_list[0].id

            selected_folder2 = db.session.get(EduFolder, folder2_id)

            if (not selected_folder2) or (selected_folder2.parent_id != selected_folder1.id) or (selected_folder2.level != 2):
                selected_folder2 = folder2_list[0]
                folder2_id = selected_folder2.id
                folder3_id = None
        else:
            folder2_id = None
            folder3_id = None

    # ===============================
    # CẤP 3
    # ===============================
    folder3_list = []
    selected_folder3 = None

    if selected_folder2:
        folder3_list = (
            EduFolder.query
            .filter_by(level=3, parent_id=selected_folder2.id)
            .order_by(EduFolder.order.asc(), EduFolder.id.asc())
            .all()
        )

        if folder3_list:
            if not folder3_id:
                folder3_id = folder3_list[0].id

            selected_folder3 = db.session.get(EduFolder, folder3_id)

            if (not selected_folder3) or (selected_folder3.parent_id != selected_folder2.id) or (selected_folder3.level != 3):
                selected_folder3 = folder3_list[0]
                folder3_id = selected_folder3.id
        else:
            folder3_id = None

    # ===============================
    # FIX CHA – CON → REDIRECT (CLEAN PARAMS)
    # - dọn folder2_id/folder3_id “rác” khi đổi folder1
    # - tránh loop do so sánh string/None
    # ===============================
    req_f1 = request.args.get("folder1_id", type=int)
    req_f2 = request.args.get("folder2_id", type=int)
    req_f3 = request.args.get("folder3_id", type=int)

    expected_f1 = folder1_id
    expected_f2 = selected_folder2.id if selected_folder2 else None
    expected_f3 = selected_folder3.id if selected_folder3 else None

    if (req_f1 != expected_f1) or (req_f2 != expected_f2) or (req_f3 != expected_f3):
        return redirect(url_for(
            "admin_educations",
            folder1_id=expected_f1,
            folder2_id=expected_f2,
            folder3_id=expected_f3
        ))

    # ===============================
    # LOAD LESSONS
    # ===============================
    lessons = []
    if selected_folder3:
        lessons = (
            Lesson.query
            .filter_by(folder3_id=selected_folder3.id)
            .order_by(Lesson.order.asc(), Lesson.id.asc())
            .all()
        )

    return render_template(
        "admin_educations.html",
        folder1_list=folder1_list,
        folder2_list=folder2_list,
        folder3_list=folder3_list,
        selected_folder1=selected_folder1,
        selected_folder2=selected_folder2,
        selected_folder3=selected_folder3,
        lessons=lessons
    )





@app.route("/admin/educations/folder/add", methods=["GET", "POST"])
@login_required
def admin_add_edu_folder():
    admin_required()

    # ===============================
    # GET → HIỂN THỊ FORM
    # ===============================
    if request.method == "GET":
        level = request.args.get("level", type=int)
        parent_id = request.args.get("parent_id", type=int)

        return render_template(
            "admin_edu_folder_add.html",
            level=level,
            parent_id=parent_id
        )

    # ===============================
    # POST → LƯU DỮ LIỆU
    # ===============================
    name = request.form.get("name", "").strip()
    level = request.form.get("level", type=int)
    parent_id = request.form.get("parent_id", type=int)

    if not name or level not in (1, 2, 3):
        flash("Thiếu dữ liệu chủ đề", "danger")
        return redirect(url_for("admin_educations"))

    order = get_next_edu_order(level, parent_id)

    edu = EduFolder(
        name=name,
        level=level,
        parent_id=parent_id,
        image=None,
        order=order,
        is_active=1
    )
    db.session.add(edu)
    db.session.flush()

    file = request.files.get("image")
    if file and file.filename:
        edu.image = save_folder_image(file, level, name)

    db.session.commit()
    flash("✅ Đã thêm chủ đề", "success")

    # Redirect giữ context
    if level == 1:
        return redirect(url_for(
            "admin_educations",
            folder1_id=edu.id
        ))

    if level == 2:
        return redirect(url_for(
            "admin_educations",
            folder1_id=parent_id,
            folder2_id=edu.id
        ))

    if level == 3:
        return redirect(url_for(
            "admin_educations",
            folder1_id=edu.parent.parent_id,
            folder2_id=parent_id,
            folder3_id=edu.id
        ))





# =====================================================
# EDU FOLDER – HỌC TAEKWONDO (TÁCH RIÊNG)
# =====================================================

class EduFolder(db.Model):
    __tablename__ = "edu_folders"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(255), nullable=False)
    image = db.Column(db.String(255))

    level = db.Column(db.Integer, nullable=False)  # 1 / 2 / 3
    parent_id = db.Column(db.Integer, db.ForeignKey("edu_folders.id"))

    parent = db.relationship(
        "EduFolder",
        remote_side=[id],
        backref="children"
    )

    order = db.Column(db.Integer, default=0)
    created_at = db.Column(SafeDateTime, default=now_vn)
    is_active = db.Column(db.Integer, default=1)  # 🔥 PHẢI CÓ




@app.route("/admin/educations/folder/<int:folder_id>/edit",
           methods=["GET", "POST"])
@login_required
def admin_edit_edu_folder(folder_id):
    admin_required()

    edu = EduFolder.query.get_or_404(folder_id)

    # ===============================
    # GET → MỞ TRANG EDIT
    # ===============================
    if request.method == "GET":
        return render_template(
            "admin_edu_folder_edit.html",
            edu=edu,
            level=edu.level
        )

    # ===============================
    # POST → LƯU CHỈNH SỬA
    # ===============================
    new_name = request.form.get("name", "").strip()

    if not new_name:
        flash("Tên chủ đề không được để trống", "danger")
        return redirect(request.url)

    old_image = edu.image
    edu.name = new_name

    file = request.files.get("image")

    # ===== Upload ảnh mới
    if file and file.filename:
        edu.image = save_folder_image(file, edu.level, new_name)

    # ===== Rename ảnh nếu chỉ đổi tên
    elif old_image:
        try:
            ext = os.path.splitext(old_image)[1]
            new_filename = f"{slugify(new_name)}{ext}"

            folder_path = os.path.dirname(old_image)
            new_path = f"{folder_path}/{new_filename}"

            abs_old = os.path.join(app.static_folder, old_image)
            abs_new = os.path.join(app.static_folder, new_path)

            if abs_old != abs_new and os.path.exists(abs_old):
                os.rename(abs_old, abs_new)
                edu.image = new_path
        except Exception as e:
            print("Rename image error:", e)

    db.session.commit()
    flash("✅ Đã cập nhật chủ đề", "success")

    # ===============================
    # Redirect giữ context
    # ===============================
    if edu.level == 1:
        return redirect(url_for("admin_educations",
                                folder1_id=edu.id))

    if edu.level == 2:
        return redirect(url_for("admin_educations",
                                folder1_id=edu.parent_id,
                                folder2_id=edu.id))

    if edu.level == 3 and edu.parent:
        return redirect(url_for("admin_educations",
                                folder1_id=edu.parent.parent_id,
                                folder2_id=edu.parent_id,
                                folder3_id=edu.id))

    return redirect(url_for("admin_educations"))




# =====================================================
# ADMIN – DELETE EDU FOLDER (SAFE)
# =====================================================
@app.route("/admin/educations/folder/<int:folder_id>/delete", methods=["POST"])
@login_required
def admin_delete_edu_folder(folder_id):
    admin_required()

    edu = EduFolder.query.get_or_404(folder_id)

    # ===============================
    # 1️⃣ Không cho xoá nếu còn con
    # ===============================
    if edu.children:
        flash("❌ Không thể xoá: chủ đề vẫn còn cấp con", "danger")
        return redirect(url_for("admin_educations"))

    # ===============================
    # 2️⃣ Không cho xoá nếu còn lesson
    # ===============================
    if edu.level == 3:
        has_lesson = Lesson.query.filter_by(folder3_id=edu.id).first()
        if has_lesson:
            flash("❌ Không thể xoá: chủ đề còn bài học", "danger")
            return redirect(url_for("admin_educations"))

    parent_id = edu.parent_id
    parent_parent_id = edu.parent.parent_id if edu.parent else None

    # ===============================
    # 3️⃣ Xoá file ảnh nếu có
    # ===============================
    if edu.image:
        abs_path = os.path.join(app.static_folder, edu.image)
        if os.path.exists(abs_path):
            os.remove(abs_path)

    db.session.delete(edu)
    db.session.commit()

    flash("🗑️ Đã xoá chủ đề", "success")

    # ===============================
    # 4️⃣ Redirect giữ context
    # ===============================
    if edu.level == 1:
        return redirect(url_for("admin_educations"))

    if edu.level == 2:
        return redirect(url_for("admin_educations",
                                folder1_id=parent_id))

    if edu.level == 3:
        return redirect(url_for("admin_educations",
                                folder1_id=parent_parent_id,
                                folder2_id=parent_id))

    return redirect(url_for("admin_educations"))





@app.route("/admin/lesson/<slug>")
@login_required
def admin_lesson(slug):
    admin_required()

    lesson_path = os.path.join(
        current_app.instance_path,
        "lessons",
        f"{slug}.json"
    )

    if not os.path.exists(lesson_path):
        return "❌ Không tìm thấy bài học", 404

    with open(lesson_path, encoding="utf-8") as f:
        lesson = json.load(f)

    return render_template(
        "lesson_editor.html",
        lesson=lesson,                     # ✅ lesson LÀ DICT
        sections=lesson.get("sections", [])
    )


def parse_pages(raw):
    """
    '1'     -> [1]
    '2-5'   -> [2,3,4,5]
    '1,3,5' -> [1,3,5]
    """
    pages = []
    raw = raw.replace(" ", "")

    for part in raw.split(","):
        if "-" in part:
            a, b = part.split("-")
            pages.extend(range(int(a), int(b) + 1))
        else:
            pages.append(int(part))

    return sorted(set(pages))


@app.route("/admin/lesson/<slug>/save", methods=["POST"])
@login_required
def save_lesson_json(slug):
    admin_required()

    titles = request.form.getlist("title[]")
    page_raws = request.form.getlist("page[]")

    lesson_path = get_lesson_json_path(slug)

    with open(lesson_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    sections = []
    for i, title in enumerate(titles):
        raw = page_raws[i].strip()
        if not title or not raw:
            continue

        sections.append({
            "id": slugify(title),
            "title": title,
            "page_raw": raw,
            "pages": parse_pages(raw)
        })


    data["sections"] = sections
    data["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(lesson_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return redirect(url_for("admin_educations"))



def load_lesson_json(slug):
    """
    Đọc file JSON bài học từ instance/lessons/<slug>.json
    """
    lesson_dir = os.path.join(app.instance_path, "lessons")
    lesson_path = os.path.join(lesson_dir, f"{slug}.json")

    if not os.path.exists(lesson_path):
        return None

    with open(lesson_path, "r", encoding="utf-8") as f:
        return json.load(f)




@app.route("/admin/lesson/editor/<slug>")
@login_required
def admin_lesson_editor(slug):
    admin_required()
    lesson = Lesson.query.filter_by(slug=slug).first_or_404()

    # ✅ đảm bảo sections là LIST trước khi đưa ra template
    sections = []
    if lesson.sections:
        try:
            sections = json.loads(lesson.sections) if isinstance(lesson.sections, str) else (lesson.sections or [])
        except Exception:
            sections = []

    return render_template("lesson_editor.html", lesson=lesson, sections=sections)


@app.route("/admin/lesson/save-sections", methods=["POST"])
@login_required
def admin_save_lesson():
    admin_required()

    data = request.get_json() or {}
    slug = (data.get("slug") or "").strip()
    sections = data.get("sections", [])

    if not slug:
        return jsonify(ok=False, error="❌ Thiếu slug bài học.")

    lesson = Lesson.query.filter_by(slug=slug).first()
    if not lesson:
        return jsonify(ok=False, error="❌ Không tìm thấy bài học.")

    try:
        lesson.sections = json.dumps(sections, ensure_ascii=False)
        db.session.commit()
        return jsonify(ok=True, message="✅ Đã lưu bài học thành công!")
    except Exception as e:
        db.session.rollback()
        return jsonify(ok=False, error=f"❌ Lưu thất bại: {str(e)}")



@app.route("/admin/lesson/create", methods=["POST"])
@login_required
def admin_create_lesson():
    admin_required()

    title = (request.form.get("title") or "").strip()
    folder3_id = request.form.get("folder3_id", type=int)

    # upload
    image_file = request.files.get("image")
    pdf_file = request.files.get("pdf")

    # kiểu bài học
    review_type = (request.form.get("review_type") or "pdf").strip().lower()
    source_url = (request.form.get("source_url") or "").strip()

    # drive kind
    drive_kind = (request.form.get("drive_kind") or "pdf").strip().lower()
    if drive_kind not in ["pdf", "video", "audio"]:
        drive_kind = "pdf"

    if not title or not folder3_id:
        flash("Thiếu dữ liệu", "danger")
        return redirect(request.referrer or url_for("admin_educations"))

    safe_type = review_type if review_type in ["pdf", "youtube", "drive", "web"] else "pdf"
    slug = slugify(title)

    # chống trùng slug
    if Lesson.query.filter_by(slug=slug).first():
        flash("Bài học đã tồn tại", "danger")
        return redirect(request.referrer or url_for("admin_educations"))

    # lấy order tiếp theo trong cùng folder3
    max_order = (
        db.session.query(db.func.max(Lesson.order))
        .filter_by(folder3_id=folder3_id)
        .scalar()
        or 0
    )

    lesson = Lesson(
        title=title,
        slug=slug,
        folder3_id=folder3_id,
        order=max_order + 1,
        review_type=safe_type,
        source_url=source_url if source_url else None,
        drive_kind=drive_kind if safe_type == "drive" else "pdf",
        pdf="Bai_hoc.pdf",
        member_plans="FREE,BASIC,PRO,VIP"
    )

    db.session.add(lesson)
    db.session.flush()

    # =========================
    # ẢNH ĐẠI DIỆN
    # =========================
    if image_file and image_file.filename:
        saved_image = save_lesson_image(image_file, lesson.title)
        if saved_image:
            lesson.image = saved_image
        else:
            flash("❌ Ảnh đại diện không hợp lệ hoặc lưu ảnh thất bại.", "danger")
            db.session.rollback()
            return redirect(request.referrer or url_for("admin_educations"))

    # =========================
    # PDF
    # =========================
    if safe_type == "pdf":
        if pdf_file and pdf_file.filename:
            if not pdf_file.filename.lower().endswith(".pdf"):
                flash("❌ File PDF không hợp lệ.", "danger")
                db.session.rollback()
                return redirect(request.referrer or url_for("admin_educations"))

            saved_pdf = save_lesson_pdf(pdf_file, lesson.slug)
            if not saved_pdf:
                flash("❌ Lưu file PDF thất bại.", "danger")
                db.session.rollback()
                return redirect(request.referrer or url_for("admin_educations"))

            lesson.pdf = saved_pdf

            try:
                convert_lesson_pdf_to_png(saved_pdf, lesson.slug)
            except Exception as e:
                db.session.rollback()
                flash(f"❌ Convert PDF sang ảnh thất bại: {e}", "danger")
                return redirect(request.referrer or url_for("admin_educations"))
        else:
            # nếu không upload thì dùng pdf mặc định
            lesson.pdf = "Bai_hoc.pdf"

        lesson.source_url = None
        lesson.drive_kind = "pdf"

    # =========================
    # YOUTUBE / DRIVE / WEB
    # =========================
    else:
        if not source_url:
            flash("❌ Vui lòng dán đường dẫn cho kiểu học đã chọn.", "danger")
            db.session.rollback()
            return redirect(request.referrer or url_for("admin_educations"))

        lesson.source_url = source_url

        if safe_type != "drive":
            lesson.drive_kind = "pdf"

    db.session.commit()
    flash("✅ Đã tạo bài học", "success")
    return redirect(request.referrer or url_for("admin_educations"))


def extract_drive_file_id(url: str) -> str | None:
    if not url:
        return None
    u = url.strip()

    # dạng: https://drive.google.com/file/d/<ID>/view
    m = re.search(r"/file/d/([^/]+)", u)
    if m:
        return m.group(1)

    # dạng: https://drive.google.com/open?id=<ID>
    # hoặc: https://drive.google.com/uc?id=<ID>&export=download
    qs = parse_qs(urlparse(u).query)
    if "id" in qs and qs["id"]:
        return qs["id"][0]

    # dạng: https://drive.google.com/drive/folders/<ID>  (không dùng cho file)
    return None


def build_drive_direct_url(share_url: str) -> str | None:
    fid = extract_drive_file_id(share_url)
    if not fid:
        return None
    # dùng uc?export=download để lấy stream trực tiếp
    return f"https://drive.google.com/uc?export=download&id={fid}"

def _drive_get_confirm_token(resp: requests.Response) -> str | None:
    # token thường nằm trong cookie dạng download_warning_*
    for k, v in resp.cookies.items():
        if k.startswith("download_warning"):
            return v
    return None

def _drive_build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    })
    return s

@app.get("/drive/stream/<file_id>")
def drive_stream(file_id):
    """
    Proxy stream Google Drive file về cùng domain.
    - Giúp PDF.js / video / audio load ổn.
    - File Drive phải share public/anyone-with-link.
    """
    sess = _drive_build_session()

    # bước 1: request download
    url = "https://drive.google.com/uc?export=download&id=" + file_id
    r = sess.get(url, stream=True, allow_redirects=True)

    # bước 2: nếu cần confirm (file lớn/scan warning)
    token = _drive_get_confirm_token(r)
    if token:
        url2 = f"https://drive.google.com/uc?export=download&id={file_id}&confirm={token}"
        r.close()
        r = sess.get(url2, stream=True, allow_redirects=True)

    # đoán content-type
    ct = r.headers.get("Content-Type", "application/octet-stream")

    def gen():
        for chunk in r.iter_content(chunk_size=1024 * 256):
            if chunk:
                yield chunk
        r.close()

    headers = {
        "Content-Type": ct,
        "Cache-Control": "no-store",
        "Accept-Ranges": "bytes",
    }

    # (Optional) nếu Ken muốn đặt filename:
    # headers["Content-Disposition"] = f'inline; filename="{file_id}"'

    return Response(stream_with_context(gen()), headers=headers, status=200)



@app.get("/lesson/<slug>")
@login_required
def lesson_view(slug):
    lesson = Lesson.query.filter_by(slug=slug).first_or_404()

    sections = []
    try:
        sections = lesson.sections or []
        if isinstance(sections, str):
            sections = json.loads(sections) if sections.strip() else []
    except Exception:
        sections = []

    rtype = (lesson.review_type or "pdf").strip().lower()
    source_url = (lesson.source_url or "").strip()

    # ===================== DRIVE =====================
    if rtype == "drive":
        file_id = extract_drive_file_id(source_url)
        if not file_id:
            flash("❌ Link Drive không hợp lệ.", "danger")
            return render_template("lesson_review.html", lesson=lesson, sections=sections)

        kind = (lesson.drive_kind or "pdf").strip().lower()
        preview_url = f"https://drive.google.com/file/d/{file_id}/preview"
        direct_url  = f"https://drive.google.com/uc?export=download&id={file_id}"

        if kind == "pdf":
            pdf_stream_url = url_for("drive_stream", file_id=file_id)
            return render_template(
                "lesson_review.html",
                lesson=lesson,
                sections=sections,
                pdf_url=pdf_stream_url,
                body_class="is-pdf is-drive-pdf"
            )

        elif kind == "video":
            video_url = url_for("drive_media", file_id=file_id)
            return render_template(
                "lesson_drive_video.html",
                lesson=lesson,
                drive_direct_url=video_url,
                preview_url=preview_url,
                body_class="is-drive-video"
            )

        elif kind == "audio":
            audio_url = url_for("drive_media", file_id=file_id)
            return render_template(
                "lesson_drive_audio.html",
                lesson=lesson,
                drive_direct_url=audio_url,
                body_class="is-drive-audio"
            )

        return render_template(
            "lesson_drive.html",
            lesson=lesson,
            sections=sections,
            kind=kind,
            preview_url=preview_url,
            direct_url=direct_url,
            filename=lesson.title
        )

    # ===================== PDF LOCAL =====================
    if rtype == "pdf":
        image_pages = get_lesson_image_pages(lesson.slug)

        # fallback: nếu chưa có ảnh mà có pdf thì tự convert 1 lần
        if not image_pages and lesson.pdf:
            try:
                convert_lesson_pdf_to_png(lesson.pdf, lesson.slug)
                image_pages = get_lesson_image_pages(lesson.slug)
            except Exception as e:
                print("[lesson_view] convert fallback error:", e)

        return render_template(
            "lesson_review.html",
            lesson=lesson,
            sections=sections,
            image_pages=image_pages,
            body_class="is-image-review"
        )

    # ===================== YOUTUBE =====================
    if rtype == "youtube":
        vid = extract_youtube_id(source_url)
        if not vid:
            flash("❌ Link Youtube không hợp lệ.", "danger")
            return render_template("lesson_review.html", lesson=lesson, sections=sections)

        embed_url = f"https://www.youtube.com/embed/{vid}?enablejsapi=1&rel=0&modestbranding=1"
        return render_template(
            "lesson_youtube.html",
            lesson=lesson,
            youtube_id=vid,
            embed_url=embed_url,
            body_class="is-youtube"
        )

    # ===================== WEB =====================
    if rtype == "web":
        iframe_url = normalize_web_url(source_url)
        return render_template(
            "lesson_web.html",
            lesson=lesson,
            iframe_url=iframe_url,
            body_class="is-web"
        )

    return render_template("lesson_review.html", lesson=lesson, sections=sections)

def get_lessons_by_folder(folder3_id):
    lesson_dir = os.path.join(current_app.instance_path, "lessons")
    results = []

    if not os.path.exists(lesson_dir):
        return results

    for file in os.listdir(lesson_dir):
        if not file.endswith(".json"):
            continue

        path = os.path.join(lesson_dir, file)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        try:
            if int(data.get("folder3_id")) != int(folder3_id):
                continue
        except:
            continue

        results.append({
            "title": data.get("title"),
            "slug": data.get("slug"),
            "image": f"uploads/lessons/{data.get('slug')}.jpg"
                if os.path.exists(
                    os.path.join(
                        current_app.static_folder,
                        "uploads",
                        "lessons",
                        f"{data.get('slug')}.jpg"
                    )
                ) else None
        })


    return results



@app.route("/admin/lesson/delete", methods=["POST"])
@login_required
def admin_delete_lesson():

    data = request.get_json() or {}
    slug = data.get("slug")

    lesson = Lesson.query.filter_by(slug=slug).first()
    if not lesson:
        return jsonify(ok=False, error="Không tìm thấy bài học")

    folder3_id = lesson.folder3_id

    # 🔥 Xoá ảnh nếu có
    if lesson.image:
        img_path = os.path.join(app.static_folder, lesson.image)
        if os.path.exists(img_path):
            os.remove(img_path)

    # ❌ Xoá record
    db.session.delete(lesson)
    db.session.commit()

    # 🔁 RE-ORDER LẠI THỨ TỰ
    lessons = (
        Lesson.query
        .filter_by(folder3_id=folder3_id)
        .order_by(Lesson.order.asc())
        .all()
    )

    for idx, l in enumerate(lessons, start=1):
        l.order = idx

    db.session.commit()

    return jsonify(ok=True)




@app.route("/admin/lesson/edit", methods=["POST"])
@login_required
def admin_edit_lesson():
    admin_required()

    slug = request.form.get("slug")
    new_title = (request.form.get("new_title") or "").strip()
    image = request.files.get("image")
    pdf_file = request.files.get("pdf")

    review_type = (request.form.get("review_type") or "").strip().lower()
    source_url  = (request.form.get("source_url") or "").strip()

    # ✅ NEW: drive_kind (pdf | video | audio)
    drive_kind = (request.form.get("drive_kind") or "pdf").strip().lower()
    if drive_kind not in ["pdf", "video", "audio"]:
        drive_kind = "pdf"

    lesson = Lesson.query.filter_by(slug=slug).first()
    if not lesson:
        flash("Không tìm thấy bài học", "danger")
        return redirect(request.referrer)

    # ✅ đổi title -> đổi slug
    if new_title:
        lesson.title = new_title
        lesson.slug = slugify(new_title)

    # ✅ đổi ảnh
    if image and image.filename:
        lesson.image = save_lesson_image(image, lesson.slug)

    # ✅ đổi PDF (nếu chọn)
    if pdf_file and pdf_file.filename:
        if not pdf_file.filename.lower().endswith(".pdf"):
            flash("❌ File PDF không hợp lệ.", "danger")
            return redirect(request.referrer)

        lesson.pdf = save_lesson_pdf(pdf_file, lesson.slug)

    # ✅ nếu lesson cũ chưa có pdf thì set default
    if not lesson.pdf:
        lesson.pdf = "Bai_hoc.pdf"

    # ✅ cập nhật kiểu học + link
    if review_type:
        if review_type not in ["pdf", "youtube", "drive", "web"]:
            flash("❌ Kiểu học không hợp lệ.", "danger")
            return redirect(request.referrer)

        lesson.review_type = review_type

        if review_type == "pdf":
            lesson.source_url = None
            if not lesson.pdf:
                lesson.pdf = "Bai_hoc.pdf"
            lesson.drive_kind = "pdf"

        else:
            # youtube/drive/web
            if not source_url:
                flash("❌ Vui lòng dán đường dẫn cho kiểu học đã chọn.", "danger")
                return redirect(request.referrer)

            lesson.source_url = source_url

            # ✅ NEW: nếu là drive thì lưu drive_kind
            if review_type == "drive":
                lesson.drive_kind = drive_kind
            else:
                lesson.drive_kind = "pdf"

    db.session.commit()

    f3 = lesson.folder
    f2 = f3.parent if f3 else None
    f1 = f2.parent if f2 else None

    return redirect(url_for(
        "admin_educations",
        folder1_id=f1.id if f1 else None,
        folder2_id=f2.id if f2 else None,
        folder3_id=f3.id if f3 else None,
        open_lesson=lesson.slug
    ))



def detect_drive_kind_by_head(file_id: str) -> str:
    """
    Trả về: 'pdf' | 'video' | 'audio' | 'pdf'(fallback)
    Chỉ ổn khi file share public.
    """
    try:
        url = f"https://drive.google.com/uc?export=download&id={file_id}"
        r = requests.head(url, allow_redirects=True, timeout=3)
        ctype = (r.headers.get("Content-Type") or "").lower()

        if "pdf" in ctype:
            return "pdf"
        if ctype.startswith("video/"):
            return "video"
        if ctype.startswith("audio/"):
            return "audio"
    except:
        pass
    return "pdf"





@app.route("/admin/lesson/save", methods=["POST"])
@login_required
def admin_lesson_save():
    data = request.get_json()
    if not data:
        return jsonify(ok=False, error="No data")

    slug = data.get("slug")
    sections = data.get("sections", [])

    if not slug:
        return jsonify(ok=False, error="Missing slug")

    lesson_file = os.path.join("instance", "lessons", f"{slug}.json")
    if not os.path.exists(lesson_file):
        return jsonify(ok=False, error="Lesson not found")

    with open(lesson_file, "r", encoding="utf-8") as f:
        lesson = json.load(f)

    lesson["sections"] = sections
    lesson["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(lesson_file, "w", encoding="utf-8") as f:
        json.dump(lesson, f, ensure_ascii=False, indent=2)

    return jsonify(ok=True)



@app.route("/admin/lesson/list")
@login_required
def admin_lesson_list_partial():
    folder3_id = request.args.get("folder3_id", type=int)

    lessons = (
        Lesson.query
        .filter_by(folder3_id=folder3_id)
        .order_by(Lesson.order.asc())
        .all()
    )

    return render_template(
        "lesson_list.html",
        lessons=lessons,
        selected_folder3={"id": folder3_id}
    )



def _safe_lower(x):
    try:
        return (x or "").strip().lower()
    except:
        return ""

def extract_youtube_id(url: str):
    url = (url or "").strip()
    if not url:
        return None

    # youtu.be/VIDEOID
    m = re.search(r"youtu\.be/([A-Za-z0-9_-]{6,})", url)
    if m:
        return m.group(1)

    # youtube.com/watch?v=VIDEOID
    m = re.search(r"[?&]v=([A-Za-z0-9_-]{6,})", url)
    if m:
        return m.group(1)

    # youtube.com/embed/VIDEOID
    m = re.search(r"/embed/([A-Za-z0-9_-]{6,})", url)
    if m:
        return m.group(1)

    return None

def extract_drive_file_id(url: str):
    url = (url or "").strip()
    if not url:
        return None

    # /file/d/<id>/
    m = re.search(r"/file/d/([A-Za-z0-9_-]+)", url)
    if m:
        return m.group(1)

    # id=<id>
    m = re.search(r"[?&]id=([A-Za-z0-9_-]+)", url)
    if m:
        return m.group(1)

    return None

def guess_drive_kind(url: str):
    u = _safe_lower(url)
    if any(k in u for k in ["mp4", "video", "mov", "mkv", "webm"]):
        return "video"
    return "pdf"

def normalize_web_url(url: str):
    url = (url or "").strip()
    if not url:
        return ""
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "https://" + url

def _safe_lower(s):
    return (s or "").strip().lower()

def extract_youtube_id(url: str):
    """
    Support:
    - https://www.youtube.com/watch?v=VIDEOID
    - https://youtu.be/VIDEOID
    - https://www.youtube.com/embed/VIDEOID
    """
    if not url:
        return None

    u = url.strip()

    # youtu.be/VIDEOID
    m = re.search(r"youtu\.be/([A-Za-z0-9_-]{6,})", u)
    if m:
        return m.group(1)

    # youtube.com/embed/VIDEOID
    m = re.search(r"youtube\.com/embed/([A-Za-z0-9_-]{6,})", u)
    if m:
        return m.group(1)

    # watch?v=VIDEOID
    m = re.search(r"[?&]v=([A-Za-z0-9_-]{6,})", u)
    if m:
        return m.group(1)

    return None

def extract_drive_file_id(url: str):
    """
    Support:
    - https://drive.google.com/file/d/FILEID/view?...
    - https://drive.google.com/open?id=FILEID
    - https://drive.google.com/uc?id=FILEID&...
    """
    if not url:
        return None

    u = url.strip()

    m = re.search(r"/file/d/([A-Za-z0-9_-]+)", u)
    if m:
        return m.group(1)

    m = re.search(r"[?&]id=([A-Za-z0-9_-]+)", u)
    if m:
        return m.group(1)

    return None

def guess_drive_kind(url: str):
    """
    Heuristic đoán pdf / video:
    - Nếu url có .pdf hoặc chứa 'pdf' => pdf
    - Nếu có .mp4/.webm/.mov => video
    - Nếu có query type=pdf|video => ưu tiên
    """
    if not url:
        return "pdf"

    u = url.lower()

    # ưu tiên query type=
    m = re.search(r"[?&]type=(pdf|video)", u)
    if m:
        return m.group(1)

    if ".pdf" in u or "pdf" in u:
        return "pdf"

    if any(ext in u for ext in [".mp4", ".webm", ".mov", ".m4v"]):
        return "video"

    # default
    return "video"

def normalize_web_url(url: str):
    if not url:
        return None
    u = url.strip()
    if u.startswith("//"):
        return "https:" + u
    if not (u.startswith("http://") or u.startswith("https://")):
        return "https://" + u
    return u




def parse_pages_safe(raw: str):
    """
    '1'     -> [1]
    '2-5'   -> [2,3,4,5]
    '1,3,5' -> [1,3,5]
    """
    try:
        raw = (raw or "").replace(" ", "")
        if not raw:
            return []
        pages = []
        for part in raw.split(","):
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                a = int(a); b = int(b)
                if a > b:
                    a, b = b, a
                pages.extend(range(a, b + 1))
            else:
                pages.append(int(part))
        # unique + sort + >0
        pages = sorted({p for p in pages if isinstance(p, int) and p > 0})
        return pages
    except:
        return []

def normalize_sections(sections):
    """
    - đảm bảo sections là list
    - mỗi section luôn có: title, page_raw, pages
    """
    if not isinstance(sections, list):
        return []

    out = []
    for s in sections:
        if not isinstance(s, dict):
            continue

        title = (s.get("title") or "").strip()
        page_raw = (s.get("page_raw") or "").strip()

        pages = s.get("pages")
        if not isinstance(pages, list) or not pages:
            # ✅ build pages từ page_raw nếu thiếu
            pages = parse_pages_safe(page_raw)

        # lọc pages cho chắc
        pages = [p for p in pages if isinstance(p, int) and p > 0]

        out.append({
            "title": title,
            "page_raw": page_raw,
            "pages": pages
        })

    return out



def drive_file_id(url: str):
    if not url:
        return None
    m = re.search(r"/file/d/([a-zA-Z0-9_-]+)", url)
    if m:
        return m.group(1)
    m = re.search(r"[?&]id=([a-zA-Z0-9_-]+)", url)
    if m:
        return m.group(1)
    return None

def drive_preview_url(url: str):
    fid = drive_file_id(url)
    if not fid:
        return None
    # preview iframe (PDF dùng tốt)
    return f"https://drive.google.com/file/d/{fid}/preview"

def drive_direct_url(url: str):
    fid = drive_file_id(url)
    if not fid:
        return None
    # direct stream cho <video>/<audio>
    return f"https://drive.google.com/uc?export=download&id={fid}"


def _extract_confirm_token(html: str):
    if not html:
        return None
    m = re.search(r"confirm=([0-9A-Za-z_]+)", html)
    return m.group(1) if m else None

def _is_login_or_block_page(html: str):
    if not html:
        return False
    s = html.lower()
    return ("accounts.google.com" in s) or ("sign in" in s) or ("login" in s)

@app.route("/media/drive/<file_id>")
def drive_media(file_id):
    base = "https://drive.google.com/uc"
    params = {"export": "download", "id": file_id}

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
        "Connection": "keep-alive",
    }

    range_header = request.headers.get("Range")
    if range_header:
        headers["Range"] = range_header

    sess = requests.Session()

    r1 = sess.get(
        base,
        params=params,
        headers=headers,
        stream=True,
        allow_redirects=True,
        timeout=(10, 60)
    )

    ctype1 = (r1.headers.get("Content-Type") or "").lower()

    if "text/html" in ctype1:
        html = ""
        try:
            html = r1.text
        except Exception:
            html = ""

        if _is_login_or_block_page(html):
            r1.close()
            return (
                "Drive đang chặn vì file chưa public. "
                "Vào Drive → Share → Anyone with the link (Viewer).",
                400
            )

        token = _extract_confirm_token(html)
        r1.close()

        if not token:
            return (
                "Không lấy được token confirm từ Drive. "
                "Thường do file chưa public hoặc Drive chặn tải.",
                400
            )

        params2 = {"export": "download", "id": file_id, "confirm": token}
        r = sess.get(
            base,
            params=params2,
            headers=headers,
            stream=True,
            allow_redirects=True,
            timeout=(10, 60)
        )
    else:
        r = r1

    ctype = (r.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype:
        r.close()
        return (
            "Drive vẫn trả về HTML (không phải file media). "
            "Kiểm tra lại quyền share hoặc thử file nhỏ hơn.",
            400
        )

    def generate():
        try:
            for chunk in r.iter_content(chunk_size=1024 * 1024):   # 1MB
                if chunk:
                    yield chunk
        finally:
            r.close()
            sess.close()

    resp = Response(
        stream_with_context(generate()),
        status=r.status_code,
        direct_passthrough=True
    )

    passthrough = [
        "Content-Type",
        "Content-Length",
        "Content-Range",
        "Accept-Ranges",
        "Content-Disposition",
        "ETag",
        "Last-Modified"
    ]
    for h in passthrough:
        if h in r.headers:
            resp.headers[h] = r.headers[h]

    if "Accept-Ranges" not in resp.headers:
        resp.headers["Accept-Ranges"] = "bytes"

    resp.headers["X-File-Name"] = file_id
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp

@app.route("/admin/lesson/detail/<slug>")
@login_required
def admin_lesson_detail(slug):
    admin_required()

    lesson = Lesson.query.filter_by(slug=slug, is_active=True).first()
    if not lesson:
        abort(404)

    sections = []
    if lesson.sections:
        try:
            sections = json.loads(lesson.sections)
        except:
            sections = []

    return render_template(
        "lesson_detail.html",
        lesson=lesson,
        sections=sections
    )



@app.route("/admin/lesson/<int:lesson_id>/folders")
@login_required
def get_lesson_folders(lesson_id):
    lesson = db.session.get(Lesson, lesson_id)
    f3 = lesson.folder
    f2 = f3.parent
    f1 = f2.parent

    return {
        "folder1_id": f1.id,
        "folder2_id": f2.id,
        "folder3_id": f3.id
    }


@app.route("/admin/lesson/change-folder", methods=["POST"])
@login_required
def admin_change_lesson_folder():
    admin_required()

    print("🔥 CHANGE FOLDER CALLED")
    print("FORM =", request.form)

    lesson_id = request.form.get("lesson_id", type=int)
    folder3_id = request.form.get("folder3_id", type=int)

    if not lesson_id:
        return jsonify(ok=False, error="Chưa chọn bài học")

    if not folder3_id:
        return jsonify(ok=False, error="Chưa chọn Chủ đề 3")

    lesson = db.session.get(Lesson, lesson_id)
    if not lesson:
        return jsonify(ok=False, error="Bài học không tồn tại")

    lesson.folder3_id = folder3_id
    db.session.commit()
    return jsonify(ok=True)

@app.route("/admin/lesson/<slug>/folder-info")
@login_required
def admin_lesson_folder_info(slug):
    admin_required()

    lesson = Lesson.query.filter_by(slug=slug).first()
    if not lesson:
        return jsonify(ok=False, error="Lesson not found")

    f3 = lesson.folder  # EduFolder level=3
    f2 = f3.parent if f3 else None
    f1 = f2.parent if f2 else None

    def dump(level, parent_id=None):
        qs = (EduFolder.query
              .filter_by(level=level, parent_id=parent_id, is_active=1)
              .order_by(EduFolder.order.asc(), EduFolder.id.asc())
              .all())
        return [{"id": f.id, "name": f.name} for f in qs]

    return jsonify(
        ok=True,
        lesson_id=lesson.id,   # ✅ THÊM DÒNG NÀY
        current={
            "f1": f1.id if f1 else None,
            "f2": f2.id if f2 else None,
            "f3": f3.id if f3 else None,
            "f1_name": f1.name if f1 else "",
            "f2_name": f2.name if f2 else "",
            "f3_name": f3.name if f3 else "",
        },
        tree={
            "f1": dump(1),
            "f2": dump(2, f1.id if f1 else None),
            "f3": dump(3, f2.id if f2 else None),
        }
    )

@app.route("/admin/lesson/<slug>/change-folder", methods=["POST"])
@login_required
def admin_change_lesson_folder_json(slug):
    admin_required()

    folder3_id = request.form.get("folder3_id", type=int)
    if not folder3_id:
        return jsonify(ok=False, error="Thiếu Chủ đề 3")

    lesson = Lesson.query.filter_by(slug=slug).first()
    if not lesson:
        return jsonify(ok=False, error="Không tìm thấy bài học")

    f3 = EduFolder.query.get(folder3_id)
    if not f3 or f3.level != 3:
        return jsonify(ok=False, error="Chủ đề 3 không hợp lệ")

    lesson.folder3_id = folder3_id
    db.session.commit()

    return jsonify(ok=True)






@app.route("/admin/topic-manager")
@login_required
def admin_topic_manager():
    admin_required()

    # ===== PHẦN HỌC = BÀI HỌC =====
    lessons = (
        Lesson.query
        .join(EduFolder, Lesson.folder3_id == EduFolder.id)
        .order_by(Lesson.order.asc(), Lesson.id.asc())
        .all()
    )

    learn_topics = []
    for l in lessons:
        f3 = l.folder
        f2 = f3.parent if f3 else None
        f1 = f2.parent if f2 else None

        f1_name = f1.name if f1 else ""
        f2_name = f2.name if f2 else ""
        f3_name = f3.name if f3 else ""

        breadcrumb = (
            f"{f1_name} › {f2_name} › {f3_name}"
            if f1 and f2 and f3 else "-"
        )

        raw_plans = (l.member_plans or "").strip()
        plans = [x.strip().upper() for x in raw_plans.split(",") if x.strip()]

        learn_topics.append({
            "id": l.id,
            "name": l.title,
            "breadcrumb": breadcrumb,
            "breadcrumb_sort": f"{f1_name} {f2_name} {f3_name}".strip().lower(),
            "member_plans": plans
        })

    # ✅ sort theo đường dẫn trước, rồi tới tên bài học
    learn_topics = sorted(
        learn_topics,
        key=lambda x: (
            x["breadcrumb_sort"],
            x["name"].lower()
        )
    )

    # ===== PHẦN ÔN TẬP =====
    quiz_folders = Folder.query \
        .filter(Folder.level == 3) \
        .order_by(Folder.order_index.asc(), Folder.id.asc()) \
        .all()

    practice_topics = []
    for f in quiz_folders:
        p2 = f.parent
        p1 = p2.parent if p2 else None

        p1_name = p1.name if p1 else ""
        p2_name = p2.name if p2 else ""
        p3_name = f.name if f else ""

        breadcrumb = (
            f"{p1_name} › {p2_name} › {p3_name}"
            if p1 and p2 else f.name
        )

        raw_plans = (f.member_plans or "").strip()
        plans = [x.strip().upper() for x in raw_plans.split(",") if x.strip()]

        practice_topics.append({
            "id": f.id,
            "name": f.name,
            "breadcrumb": breadcrumb,
            "breadcrumb_sort": f"{p1_name} {p2_name} {p3_name}".strip().lower(),
            "member_plans": plans
        })

    practice_topics = sorted(
        practice_topics,
        key=lambda x: (
            x["breadcrumb_sort"],
            x["name"].lower()
        )
    )

    return render_template(
        "admin_topic_manager.html",
        learn_topics=learn_topics,
        practice_topics=practice_topics
    )


@app.route("/admin/edu-folder/toggle", methods=["POST"])
@login_required
def toggle_edu_folder():
    admin_required()

    folder_id = request.json.get("id")
    folder = db.session.get(EduFolder, folder_id)

    if not folder:
        return jsonify({"error": "Not found"}), 404

    folder.is_active = 0 if folder.is_active else 1
    db.session.commit()

    return jsonify({"ok": True})




@app.route("/admin/topic/toggle", methods=["POST"])
@login_required
def toggle_topic():
    data = request.get_json()
    topic_id = data.get("id")

    topic = db.session.get(Folder, topic_id)
    if not topic:
        return jsonify({"error": "Not found"}), 404

    topic.is_active_practice = 0 if topic.is_active_practice else 1
    db.session.commit()

    return jsonify({"ok": True})

@app.route("/admin/lesson/member-setup", methods=["POST"])
@login_required
def admin_lesson_member_setup():
    admin_required()

    data = request.get_json(silent=True) or {}
    lesson_id = data.get("id")
    plans = data.get("plans") or []

    lesson = db.session.get(Lesson, lesson_id)
    if not lesson:
        return jsonify({"ok": False, "message": "Không tìm thấy bài học"}), 404

    valid = ["FREE", "BASIC", "PRO", "VIP", "ADMIN"]

    clean_plans = []
    for p in plans:
        p = str(p).strip().upper()
        if p in valid and p not in clean_plans:
            clean_plans.append(p)

    lesson.member_plans = ",".join(clean_plans) if clean_plans else ""
    db.session.commit()

    return jsonify({
        "ok": True,
        "member_plans": clean_plans
    })

@app.route("/admin/practice/member-setup", methods=["POST"])
@login_required
def admin_practice_member_setup():
    admin_required()

    data = request.get_json(silent=True) or {}
    folder_id = data.get("id")
    plans = data.get("plans") or []

    folder = db.session.get(Folder, folder_id)
    if not folder:
        return jsonify({"ok": False, "message": "Không tìm thấy chủ đề ôn tập"}), 404

    valid = ["FREE", "BASIC", "PRO", "VIP", "ADMIN"]

    clean_plans = []
    for p in plans:
        p = str(p).strip().upper()
        if p in valid and p not in clean_plans:
            clean_plans.append(p)

    folder.member_plans = ",".join(clean_plans) if clean_plans else ""
    db.session.commit()

    return jsonify({
        "ok": True,
        "member_plans": clean_plans
    })

@app.route("/admin/practice/question-plans/<int:folder_id>")
@login_required
def admin_practice_question_plans(folder_id):
    admin_required()

    folder = db.session.get(Folder, folder_id)
    if not folder or folder.level != 3:
        return jsonify({"ok": False, "message": "Không tìm thấy chủ đề ôn tập"}), 404

    folder_plans = [x.strip().upper() for x in (folder.member_plans or "").split(",") if x.strip()]

    questions = (
        Question.query
        .filter_by(folder_id=folder_id)
        .order_by(Question.id.asc())
        .all()
    )

    items = []
    for idx, q in enumerate(questions, start=1):
        q_plans = [x.strip().upper() for x in (q.member_plans or "").split(",") if x.strip()]
        items.append({
            "id": q.id,
            "number": idx,
            "text": q.text,
            "member_plans": q_plans
        })

    return jsonify({
        "ok": True,
        "folder_id": folder.id,
        "folder_name": folder.name,
        "folder_plans": folder_plans,
        "questions": items
    })

@app.route("/admin/practice/question-plans/save", methods=["POST"])
@login_required
def admin_practice_question_plans_save():
    admin_required()

    data = request.get_json(silent=True) or {}
    folder_id = data.get("folder_id")
    items = data.get("items") or []

    folder = db.session.get(Folder, folder_id)
    if not folder or folder.level != 3:
        return jsonify({"ok": False, "message": "Không tìm thấy chủ đề ôn tập"}), 404

    folder_plans = [x.strip().upper() for x in (folder.member_plans or "").split(",") if x.strip()]
    valid = {"FREE", "BASIC", "PRO", "VIP", "ADMIN"}

    qids = [int(x.get("id")) for x in items if x.get("id")]
    questions = Question.query.filter(Question.id.in_(qids), Question.folder_id == folder.id).all()
    qmap = {q.id: q for q in questions}

    for row in items:
        try:
            qid = int(row.get("id"))
        except:
            continue

        q = qmap.get(qid)
        if not q:
            continue

        clean = []
        for p in row.get("member_plans") or []:
            p = str(p).strip().upper()
            if p in valid and p in folder_plans and p not in clean:
                clean.append(p)

        q.member_plans = ",".join(clean) if clean else ""

    db.session.commit()
    return jsonify({"ok": True})

@app.route("/admin/educations/folder/move", methods=["POST"])
@login_required
def admin_move_edu_folder():
    admin_required()

    data = request.get_json()
    edu_id = data.get("id")
    level = data.get("level")
    parent_id = data.get("parent_id")
    direction = data.get("direction")

    if not edu_id or not level or not direction:
        return jsonify(ok=False, error="Thiếu dữ liệu")

    edu = EduFolder.query.get(edu_id)
    if not edu:
        return jsonify(success=False, message="Không tìm thấy chủ đề")

    q = EduFolder.query.filter_by(level=int(level), is_active=1)

    if parent_id:
        q = q.filter_by(parent_id=int(parent_id))
    else:
        q = q.filter(EduFolder.parent_id.is_(None))

    siblings = q.order_by(EduFolder.order.asc()).all()
    ids = [f.id for f in siblings]

    idx = ids.index(edu.id)

    if direction == "up" and idx > 0:
        other = siblings[idx - 1]
    elif direction == "down" and idx < len(siblings) - 1:
        other = siblings[idx + 1]
    else:
        return jsonify(success=True)

    edu.order, other.order = other.order, edu.order
    db.session.commit()

    return jsonify(success=True)


@app.route("/admin/practice/folder/move", methods=["POST"])
@login_required
def admin_move_practice_folder():
    admin_required()

    data = request.get_json()
    fid = data.get("id")
    level = data.get("level")
    parent_id = data.get("parent_id")
    direction = data.get("direction")

    if not fid or not direction:
        return jsonify(success=False)

    folder = Folder.query.get(fid)
    if not folder:
        return jsonify(success=False)

    q = Folder.query.filter_by(level=level)

    if parent_id:
        q = q.filter_by(parent_id=parent_id)
    else:
        q = q.filter(Folder.parent_id.is_(None))

    # 🔥 PHẢI DÙNG order_index
    siblings = q.order_by(Folder.order_index.asc()).all()

    ids = [f.id for f in siblings]
    idx = ids.index(folder.id)

    if direction == "up" and idx > 0:
        other = siblings[idx - 1]
    elif direction == "down" and idx < len(siblings) - 1:
        other = siblings[idx + 1]
    else:
        return jsonify(success=True)

    # 🔥 SWAP order_index
    folder.order_index, other.order_index = other.order_index, folder.order_index
    db.session.commit()

    return jsonify(success=True)





@app.route("/admin/lesson/move", methods=["POST"])
@login_required
def admin_move_lesson():

    data = request.get_json() or {}

    folder3_id = int(data.get("folder3_id"))
    slug = data.get("slug")
    direction = data.get("direction")

    if not folder3_id or not slug or direction not in ("up", "down"):
        return jsonify(ok=False, error="Thiếu dữ liệu")

    current = Lesson.query.filter_by(
        slug=slug,
        folder3_id=folder3_id
    ).first()

    if not current:
        return jsonify(ok=False, error="Không tìm thấy bài học")

    if direction == "up":
        neighbor = (
            Lesson.query
            .filter(
                Lesson.folder3_id == folder3_id,
                Lesson.order < current.order
            )
            .order_by(Lesson.order.desc())
            .first()
        )
    else:
        neighbor = (
            Lesson.query
            .filter(
                Lesson.folder3_id == folder3_id,
                Lesson.order > current.order
            )
            .order_by(Lesson.order.asc())
            .first()
        )

    if not neighbor:
        return jsonify(ok=True)

    current.order, neighbor.order = neighbor.order, current.order
    db.session.commit()

    return jsonify(ok=True)


















# ===============================
# EXAM
# ===============================
@app.route("/exam")
@login_required
def exam_home():

    # ===============================
    # Lấy tất cả câu hỏi thuộc folder3
    # ===============================
    all_questions = (
        Question.query
        .join(Folder, Question.folder_id == Folder.id)
        .filter(
            Folder.level == 3,
            Folder.is_active_practice == 1
        )
        .order_by(Question.id.asc())
        .all()
    )

    # ===============================
    # Lọc theo gói
    # ===============================
    questions = []

    for q in all_questions:

        folder = q.folder

        # folder phải được phép
        if not can_access_plans(folder.member_plans):
            continue

        # question phải được phép
        if not can_access_plans(q.member_plans):
            continue

        questions.append(q)

    return render_template(
        "admin_exam.html",
        questions=questions
    )


@app.route("/exam/question/<int:qid>")
@login_required
def exam_get_question(qid):
    q = db.session.get(Question, qid)
    if not q:
        return jsonify(ok=False, error="Không tìm thấy câu hỏi")

    payload = question_answers_payload(q, shuffle_answers=True)
    correct_indexes = parse_correct_indexes(q)

    qtype = (q.type or "mcq").strip().lower()
    if qtype in ("truefalse", "true_false", "tf"):
        qtype = "boolean"
    elif qtype in ("multiple", "multiple_choice_multi"):
        qtype = "multi"
    else:
        qtype = "mcq" if qtype not in ("mcq", "boolean", "multi") else qtype

    return jsonify(
        ok=True,
        id=q.id,
        text=q.text,
        type=qtype,
        correct_count=len(correct_indexes),
        choices=[
            {
                "id": item["orig_idx"],
                "text": item["text"],
                "label": item["label"]
            }
            for item in payload
        ]
    )


@app.route("/exam/check", methods=["POST"])
@login_required
def exam_check():
    data = request.get_json(silent=True) or {}

    qid = data.get("question_id")
    q = db.session.get(Question, qid)
    if not q:
        return jsonify(ok=False, error="Không tìm thấy câu hỏi")

    qtype = (q.type or "mcq").strip().lower()
    if qtype in ("truefalse", "true_false", "tf"):
        qtype = "boolean"
    elif qtype in ("multiple", "multiple_choice_multi"):
        qtype = "multi"
    else:
        qtype = "mcq" if qtype not in ("mcq", "boolean", "multi") else qtype

    correct_indexes = parse_correct_indexes(q)

    valid_answer_indexes = {
        i for i, txt in enumerate(question_answer_texts(q), start=1)
        if (txt or "").strip()
    }

    if qtype == "multi":
        raw_ids = data.get("choice_ids", [])

        if not isinstance(raw_ids, list):
            return jsonify(ok=False, error="Dữ liệu đáp án không hợp lệ")

        chosen_indexes = []
        for x in raw_ids:
            s = str(x).strip()
            if s.isdigit():
                chosen_indexes.append(int(s))

        chosen_indexes = sorted(set(chosen_indexes))

        if not chosen_indexes:
            return jsonify(ok=False, error="Vui lòng chọn ít nhất 1 đáp án")

        if any(i not in valid_answer_indexes for i in chosen_indexes):
            return jsonify(ok=False, error="Có đáp án không hợp lệ")

        return jsonify(
            ok=True,
            correct=(set(chosen_indexes) == correct_indexes),
            type="multi",
            chosen_indexes=chosen_indexes,
            correct_indexes=sorted(list(correct_indexes))
        )

    choice_id = data.get("choice_id")

    try:
        choice_id = int(choice_id)
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Đáp án không hợp lệ")

    if choice_id not in valid_answer_indexes:
        return jsonify(ok=False, error="Đáp án không hợp lệ")

    return jsonify(
        ok=True,
        correct=(choice_id in correct_indexes),
        type=qtype,
        chosen_index=choice_id,
        correct_indexes=sorted(list(correct_indexes))
    )

class Lesson(db.Model):
    __tablename__ = "lessons"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False)

    image = db.Column(db.String(255))
    pdf = db.Column(db.String(255), default="Bai_hoc.pdf")

    review_type = db.Column(db.String(20), default="pdf")
    source_url  = db.Column(db.Text, nullable=True)

    drive_kind = db.Column(db.String(20), default="pdf")  # pdf | video | audio

    folder3_id = db.Column(
        db.Integer,
        db.ForeignKey("edu_folders.id"),
        nullable=False
    )

    folder = db.relationship("EduFolder")
    order = db.Column(db.Integer, default=0)

    created_at = db.Column(SafeDateTime, default=now_vn)
    sections = db.Column(db.Text)   # lưu JSON string

    member_plans = db.Column(db.String(100), default="FREE,BASIC,PRO,VIP")

class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False, default="admin")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=True)
    target_url = db.Column(db.String(500), nullable=True)
    icon = db.Column(db.String(20), default="🔔")
    is_read = db.Column(db.Boolean, default=False)

    # SỬA DÒNG NÀY
    created_at = db.Column(SafeDateTime, default=now_vn)

    user = db.relationship("User", foreign_keys=[user_id])

    action_type = db.Column(db.String(50), nullable=True)
    ref_user_id = db.Column(db.Integer, nullable=True)
    ref_plan_code = db.Column(db.String(50), nullable=True)
    ref_months = db.Column(db.Integer, nullable=True)
    is_done = db.Column(db.Boolean, default=False)


def load_lessons_by_folder3(folder3_id):
    lessons = (
        Lesson.query
        .filter_by(folder3_id=folder3_id)
        .order_by(Lesson.order.asc())
        .all()
    )

    if not current_user.is_authenticated:
        return []

    user_plan = norm_plan(get_effective_member())

    admin_full = (
        getattr(current_user, "role", "") == "admin"
        and not is_admin_preview_mode()
    )

    if admin_full:
        return lessons

    allowed_lessons = []
    for lesson in lessons:
        raw = (lesson.member_plans or "").strip()
        plans = [x.strip().upper() for x in raw.split(",") if x.strip()]

        # ✅ không set gói nào = không hiện
        if not plans:
            continue

        if user_plan in plans:
            allowed_lessons.append(lesson)

    return [lesson for lesson in lessons if can_access_plans(lesson.member_plans)]














class MemberPlan(db.Model):
    __tablename__ = "member_plan"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)   # BASIC / PRO / VIP
    name = db.Column(db.String(100), nullable=False)
    price_monthly = db.Column(db.Integer, nullable=False, default=0)
    description = db.Column(db.Text, nullable=True)
    features_text = db.Column(db.Text, nullable=True)  # mỗi dòng 1 quyền lợi
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(VN_TZ), onupdate=lambda: datetime.now(VN_TZ))


class PromotionCampaign(db.Model):
    __tablename__ = "promotion_campaign"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)

    # all / selected
    target_mode = db.Column(db.String(20), nullable=False, default="all")

    # percent / fixed
    discount_type = db.Column(db.String(20), nullable=False, default="percent")
    discount_value = db.Column(db.Integer, nullable=False, default=0)

    # áp dụng cho plan nào: BASIC,PRO,VIP hoặc ALL
    plan_codes = db.Column(db.String(100), nullable=False, default="ALL")

    start_at = db.Column(db.DateTime, nullable=False)
    end_at = db.Column(db.DateTime, nullable=False)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(VN_TZ), nullable=False)

    code = db.Column(db.String(50), unique=True, nullable=True)
    promo_kind = db.Column(db.String(20), nullable=False, default="campaign")


class PromotionUser(db.Model):
    __tablename__ = "promotion_user"

    id = db.Column(db.Integer, primary_key=True)
    promotion_id = db.Column(db.Integer, db.ForeignKey("promotion_campaign.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    promotion = db.relationship("PromotionCampaign", backref="promotion_users")
    user = db.relationship("User", backref="promotion_links")

    __table_args__ = (
        db.UniqueConstraint("promotion_id", "user_id", name="uq_promotion_user"),
    )

class PaymentBankSetting(db.Model):
    __tablename__ = "payment_bank_setting"

    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(150), nullable=False)
    bank_code = db.Column(db.String(50), nullable=False)   # vd: ACB, MBBANK, BIDV...
    bank_bin = db.Column(db.String(20), nullable=True)     # vd: 970416
    bank_name = db.Column(db.String(150), nullable=False)
    account_no = db.Column(db.String(50), nullable=False)
    note_default = db.Column(db.String(255), nullable=False, default="Theo ghi chú phần thông tin đơn hàng bên trên")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(VN_TZ), onupdate=lambda: datetime.now(VN_TZ))

def seed_member_plans():
    defaults = [
        {
            "code": "BASIC",
            "name": "Taekwondo Cơ Bản",
            "price_monthly": 300000,
            "description": "Nội dung gói cơ bản",
            "features_text": "+ Kỹ thuật cơ bản",
            "sort_order": 1,
        },
        {
            "code": "PRO",
            "name": "Taekwondo Nâng cao",
            "price_monthly": 500000,
            "description": "Nội dung gói nâng cao",
            "features_text": "+ Kỹ thuật cơ bản\n+ Kỹ thuật nâng cao\n+ Nội dung thi đẳng",
            "sort_order": 2,
        },
        {
            "code": "VIP",
            "name": "Taekwondo Cao Cấp",
            "price_monthly": 800000,
            "description": "Nội dung gói cao cấp",
            "features_text": "+ Kỹ thuật cơ bản\n+ Kỹ thuật nâng cao\n+ Nội dung thi đẳng\n+ Kỹ thuật cao cấp\n+ Võ nhạc",
            "sort_order": 3,
        },
    ]

    for item in defaults:
        exists = MemberPlan.query.filter_by(code=item["code"]).first()
        if not exists:
            db.session.add(MemberPlan(**item))

    bank = PaymentBankSetting.query.first()
    if not bank:
        db.session.add(PaymentBankSetting(
            account_name="NGUYEN THIEN PHUNG",
            bank_code="ACB",
            bank_bin="970416",
            bank_name="Ngân hàng Á Châu",
            account_no="682657",
            note_default="Theo ghi chú phần thông tin đơn hàng bên trên",
        ))

    db.session.commit()


@app.route("/admin/subscription-manager")
@login_required
def admin_subscription_manager():
    if current_user.role != "admin":
        abort(403)

    plans = MemberPlan.query.order_by(MemberPlan.sort_order.asc()).all()
    promotions = PromotionCampaign.query.order_by(PromotionCampaign.created_at.desc()).all()
    bank = PaymentBankSetting.query.filter_by(is_active=True).first()

    users = (
        User.query
        .filter(User.role != "admin")
        .order_by(User.id.asc())
        .all()
    )

    now = datetime.now(VN_TZ).replace(tzinfo=None)

    return render_template(
        "admin_subscription_manager.html",
        plans=plans,
        promotions=promotions,
        bank=bank,
        users=users,
        now_dt=now,
    )

@app.post("/admin/subscription-manager/plan/<int:plan_id>/save")
@login_required
def admin_save_plan(plan_id):
    if current_user.role != "admin":
        abort(403)

    plan = MemberPlan.query.get_or_404(plan_id)
    plan.name = request.form.get("name", "").strip()
    plan.price_monthly = int(request.form.get("price_monthly", 0) or 0)
    plan.description = request.form.get("description", "").strip()
    plan.features_text = request.form.get("features_text", "").strip()

    db.session.commit()
    flash(f"Đã lưu gói {plan.code}", "success")
    return redirect(url_for("admin_subscription_manager"))


from datetime import datetime

@app.post("/admin/subscription-manager/promotion/create")
@login_required
def admin_create_promotion():
    if current_user.role != "admin":
        abort(403)

    title = request.form.get("title", "").strip()
    code = request.form.get("code", "").strip().upper()
    promo_kind = request.form.get("promo_kind", "campaign").strip().lower()
    target_mode = request.form.get("target_mode", "all").strip()
    plan_codes = request.form.get("plan_codes", "ALL").strip().upper()
    discount_type = request.form.get("discount_type", "percent").strip()
    discount_value = int(request.form.get("discount_value", 0) or 0)

    start_at = datetime.fromisoformat(request.form.get("start_at"))
    end_at = datetime.fromisoformat(request.form.get("end_at"))

    if not title:
        flash("Thiếu tên khuyến mãi", "danger")
        return redirect(url_for("admin_subscription_manager"))

    if promo_kind not in ("campaign", "voucher"):
        flash("Loại khuyến mãi không hợp lệ", "danger")
        return redirect(url_for("admin_subscription_manager"))

    if promo_kind == "voucher" and not code:
        flash("Phiếu khuyến mãi phải có mã", "danger")
        return redirect(url_for("admin_subscription_manager"))

    if code:
        existed = PromotionCampaign.query.filter_by(code=code).first()
        if existed:
            flash("Mã khuyến mãi đã tồn tại", "danger")
            return redirect(url_for("admin_subscription_manager"))

    promo = PromotionCampaign(
        title=title,
        code=code if code else None,
        promo_kind=promo_kind,
        target_mode=target_mode,
        plan_codes=plan_codes,
        discount_type=discount_type,
        discount_value=discount_value,
        start_at=start_at,
        end_at=end_at,
        is_active=True,
    )
    db.session.add(promo)
    db.session.flush()

    selected_users = []
    if target_mode == "selected":
        raw_ids = request.form.get("selected_user_ids", "")
        user_ids = []
        for x in raw_ids.split(","):
            x = x.strip()
            if x.isdigit():
                user_ids.append(int(x))

        for uid in set(user_ids):
            db.session.add(PromotionUser(
                promotion_id=promo.id,
                user_id=uid
            ))
            selected_users.append(uid)

    db.session.commit()

    # Gửi phiếu giảm giá riêng cho user được chọn
    if promo_kind == "voucher" and selected_users:
        send_voucher_to_selected_users(promo.id)

    flash("Đã tạo khuyến mãi", "success")
    return redirect(url_for("admin_subscription_manager"))

@app.route("/admin/update-promotion", methods=["POST"])
@login_required
def admin_update_promotion():
    promo_id = request.form.get("promo_id", type=int)
    promo = PromotionCampaign.query.get_or_404(promo_id)

    promo.title = (request.form.get("title") or "").strip()
    promo.code = (request.form.get("code") or "").strip() or None
    promo.target_mode = (request.form.get("target_mode") or "all").strip()
    promo.plan_codes = (request.form.get("plan_codes") or "ALL").strip()
    promo.discount_type = (request.form.get("discount_type") or "fixed").strip()

    discount_value_raw = (request.form.get("discount_value") or "0").replace(",", "").strip()
    try:
        promo.discount_value = float(discount_value_raw or 0)
    except:
        promo.discount_value = 0

    start_at_raw = request.form.get("start_at") or ""
    end_at_raw = request.form.get("end_at") or ""

    try:
        promo.start_at = datetime.strptime(start_at_raw, "%Y-%m-%dT%H:%M") if start_at_raw else None
        promo.end_at = datetime.strptime(end_at_raw, "%Y-%m-%dT%H:%M") if end_at_raw else None
    except ValueError:
        flash("Thời gian khuyến mãi không hợp lệ.", "error")
        return redirect(url_for("admin_subscription_manager"))

    if promo.discount_type == "percent":
        if promo.discount_value < 0:
            promo.discount_value = 0
        if promo.discount_value > 100:
            promo.discount_value = 100

    db.session.commit()
    flash("Đã cập nhật khuyến mãi thành công.", "success")
    return redirect(url_for("admin_subscription_manager"))

@app.post("/admin/subscription-manager/promotion/<int:promo_id>/delete")
@login_required
def admin_delete_promotion(promo_id):
    if current_user.role != "admin":
        abort(403)

    promo = PromotionCampaign.query.get_or_404(promo_id)

    PromotionUser.query.filter_by(promotion_id=promo.id).delete()
    db.session.delete(promo)
    db.session.commit()

    flash("Đã xóa khuyến mãi", "success")
    return redirect(url_for("admin_subscription_manager"))



@app.post("/admin/subscription-manager/bank/save")
@login_required
def admin_save_bank_setting():
    if current_user.role != "admin":
        abort(403)

    bank = PaymentBankSetting.query.first()
    if not bank:
        bank = PaymentBankSetting()
        db.session.add(bank)

    bank.account_name = request.form.get("account_name", "").strip()
    bank.bank_code = request.form.get("bank_code", "").strip()
    bank.bank_name = request.form.get("bank_name", "").strip()
    bank.bank_bin = request.form.get("bank_bin", "").strip()
    bank.account_no = request.form.get("account_no", "").strip()
    bank.note_default = request.form.get("note_default", "Theo ghi chú phần thông tin đơn hàng bên trên").strip()

    db.session.commit()
    flash("Đã cập nhật thông tin ngân hàng", "success")
    return redirect(url_for("admin_subscription_manager"))

def get_active_promotion_for_user(user, plan_code):
    now = datetime.now(VN_TZ).replace(tzinfo=None)

    promos = PromotionCampaign.query.filter(
        PromotionCampaign.is_active == True,
        PromotionCampaign.promo_kind == "campaign",
        PromotionCampaign.start_at <= now,
        PromotionCampaign.end_at >= now
    ).all()

    matched = []
    for p in promos:
        if p.plan_codes not in ("ALL", plan_code):
            continue

        if p.target_mode == "all":
            matched.append(p)
            continue

        has_user = PromotionUser.query.filter_by(
            promotion_id=p.id,
            user_id=user.id
        ).first()
        if has_user:
            matched.append(p)

    if not matched:
        return None

    matched.sort(key=lambda x: x.discount_value, reverse=True)
    return matched[0]

def get_promotion_by_code_for_user(user, code, plan_code):
    code = (code or "").strip().upper()
    if not code:
        return None, "Không có mã khuyến mãi."

    now = datetime.now(VN_TZ).replace(tzinfo=None)

    promo = PromotionCampaign.query.filter(
        PromotionCampaign.is_active == True,
        PromotionCampaign.promo_kind == "voucher",
        PromotionCampaign.code == code,
        PromotionCampaign.start_at <= now,
        PromotionCampaign.end_at >= now
    ).first()

    if not promo:
        return None, "Mã khuyến mãi không hợp lệ hoặc đã hết hạn."

    if promo.plan_codes not in ("ALL", plan_code):
        return None, "Khuyến mãi không dành cho gói này."

    if promo.target_mode == "selected":
        has_user = PromotionUser.query.filter_by(
            promotion_id=promo.id,
            user_id=user.id
        ).first()
        if not has_user:
            return None, "Khuyến mãi này không áp dụng cho tài khoản của bạn."

    return promo, ""

@app.post("/renew/check-promo")
def renew_check_promo():
    try:
        data = request.get_json(silent=True) or request.form or {}

        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()

        user = None
        if username:
            user = User.query.filter_by(username=username).first()
        if not user and email:
            user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"ok": False, "message": "Không tìm thấy user."}), 400

        plan_code = norm_plan(data.get("plan_code"))
        if plan_code == "FREE":
            return jsonify({"ok": False, "message": "Gói đăng ký không hợp lệ."}), 400

        promo_code = (data.get("promo_code") or "").strip().upper()
        if not promo_code:
            return jsonify({"ok": False, "message": "Vui lòng nhập mã khuyến mãi."}), 400

        try:
            raw_total = int(data.get("raw_total", 0) or 0)
        except Exception:
            raw_total = 0

        try:
            discount = int(data.get("discount", 0) or 0)
        except Exception:
            discount = 0

        promo, promo_msg = get_promotion_by_code_for_user(user, promo_code, plan_code)
        if not promo:
            return jsonify({"ok": False, "message": promo_msg}), 400

        after_month_discount = max(raw_total - discount, 0)

        if str(promo.discount_type or "").lower() == "percent":
            promo_discount = int(after_month_discount * float(promo.discount_value or 0) / 100)
        else:
            promo_discount = int(promo.discount_value or 0)

        promo_discount = max(promo_discount, 0)

        return jsonify({
            "ok": True,
            "promo_code": promo.code,
            "promo_title": promo.title,
            "promo_discount": promo_discount
        })

    except Exception as e:
        print("[renew_check_promo] ERROR:", e)
        return jsonify({"ok": False, "message": "Lỗi kiểm tra mã khuyến mãi."}), 500

def calc_discounted_price(base_price, promo):
    if not promo:
        return base_price

    if promo.discount_type == "percent":
        final_price = base_price - int(base_price * promo.discount_value / 100)
    else:
        final_price = base_price - promo.discount_value

    return max(final_price, 0)

def build_member_plan_cards_for_user(user=None):
    plans = (
        MemberPlan.query
        .filter_by(is_active=True)
        .order_by(MemberPlan.sort_order.asc())
        .all()
    )

    # Nếu chưa có gói nào thì tự seed lại
    if not plans:
        try:
            seed_member_plans()
            plans = (
                MemberPlan.query
                .filter_by(is_active=True)
                .order_by(MemberPlan.sort_order.asc())
                .all()
            )
        except Exception as e:
            print("[build_member_plan_cards_for_user] seed failed:", e)
            return []

    cards = []
    for p in plans:
        promo = get_active_promotion_for_user(user, p.code) if user else None
        final_price = calc_discounted_price(p.price_monthly, promo)

        cards.append({
            "code": p.code,
            "name": p.name,
            "price_monthly": int(p.price_monthly or 0),
            "final_price": int(final_price or 0),
            "description": p.description or "",
            "features": [x.strip() for x in (p.features_text or "").splitlines() if x.strip()],
            "promo": promo,
        })
    return cards


def get_active_bank_setting():
    return PaymentBankSetting.query.filter_by(is_active=True).first()


def calc_plan_checkout_for_user(user, plan_code: str, months: int):
    plan_code = norm_plan(plan_code)
    months = max(1, int(months or 1))

    plan = MemberPlan.query.filter_by(code=plan_code, is_active=True).first()
    if not plan:
        raise ValueError("Gói không tồn tại hoặc đang tắt.")

    promo = get_active_promotion_for_user(user, plan_code) if user else None

    unit_price = int(plan.price_monthly or 0)
    promo_price = int(calc_discounted_price(unit_price, promo) or 0)

    raw_total = unit_price * months
    final_total = promo_price * months
    discount = max(raw_total - final_total, 0)

    return {
        "plan": plan,
        "promo": promo,
        "unit_price": unit_price,
        "promo_price": promo_price,
        "raw_total": raw_total,
        "discount": discount,
        "final_total": final_total,
    }


from urllib.parse import quote


def build_vietqr_url(bank_code, account_no, amount, add_info, account_name):
    bank_code = (bank_code or "").strip()
    account_no = (account_no or "").strip()
    account_name = (account_name or "").strip()
    add_info = (add_info or "").strip()

    return (
        f"https://img.vietqr.io/image/{bank_code}-{account_no}-compact2.png"
        f"?amount={int(amount)}"
        f"&addInfo={quote(add_info)}"
        f"&accountName={quote(account_name)}"
    )


def make_qr_for_checkout(user, plan_code, months):
    bank = get_active_bank_setting()
    if not bank:
        return ""

    checkout = calc_plan_checkout_for_user(user, plan_code, months)
    transfer_note = f"{user.username} - {norm_plan(plan_code)} - {months}m"

    return build_vietqr_url(
        bank_code=bank.bank_code,
        account_no=bank.account_no,
        amount=checkout["final_total"],
        add_info=transfer_note,
        account_name=bank.account_name
    )







if __name__ == "__main__":
    with app.app_context():

        db.create_all()
        ensure_schema()
        ensure_user_pref_columns()
        ensure_lesson_pdf_column()
        ensure_lesson_media_columns()
        ensure_lesson_member_plans_column()
        ensure_folder_member_plans_column()
        ensure_question_member_plans_column()
        ensure_promotion_code_column()   # <- THÊM DÒNG NÀY
        ensure_promotion_kind_column()
        migrate_user_table()
        migrate_notification_table()
        seed_admin()
        seed_member_plans()

    app.run(debug=True, use_reloader=False)











