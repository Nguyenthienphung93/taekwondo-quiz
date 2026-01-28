import random
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, redirect, url_for, flash, render_template, session, abort
import sqlite3
import os
from sqlalchemy.exc import IntegrityError
import secrets
import smtplib
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
import re
import unicodedata
import re
import unicodedata

def slugify(text):
    # xử lý riêng cho đ/Đ
    text = text.replace("đ", "d").replace("Đ", "D")

    # bỏ dấu tiếng Việt
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")

    # thay ký tự lạ bằng _
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text)

    return text.strip("_").lower()




app = Flask(__name__)
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



def save_folder_image(file, level, folder_name):
    if not file or file.filename == "":
        return None

    ext = os.path.splitext(secure_filename(file.filename))[1].lower()
    safe_name = slugify(folder_name)

    filename = f"{safe_name}{ext}"
    sub_dir = f"folder{level}"

    upload_dir = os.path.join(app.static_folder, "uploads", sub_dir)
    os.makedirs(upload_dir, exist_ok=True)

    save_path = os.path.join(upload_dir, filename)
    file.save(save_path)

    return f"uploads/{sub_dir}/{filename}"




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
    """User preferences & trạng thái tài khoản"""
    with app.app_context():
        try:
            cols = [r[1] for r in db.session.execute(
                db.text("PRAGMA table_info(user)")
            ).all()]

            def add(col, sql):
                if col not in cols:
                    db.session.execute(db.text(sql))

            add("pref_num_questions",
                "ALTER TABLE user ADD COLUMN pref_num_questions INTEGER")

            add("pref_time_per_q",
                "ALTER TABLE user ADD COLUMN pref_time_per_q INTEGER")

            add("nickname",
                "ALTER TABLE user ADD COLUMN nickname VARCHAR(120)")

            add("email",
                "ALTER TABLE user ADD COLUMN email VARCHAR(120)")

            add("must_change_password",
                "ALTER TABLE user ADD COLUMN must_change_password BOOLEAN DEFAULT 0")

            add("is_active",
                "ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1")

            add("is_deleted",
                "ALTER TABLE user ADD COLUMN is_deleted BOOLEAN DEFAULT 0")

            db.session.commit()

        except Exception as e:
            print("[DB] ensure_user_pref_columns error:", e)




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
        return redirect(url_for("sets"))

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
    return redirect(url_for("sets"))             # ✅ C.2




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



# ===================== MODELS =====================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    pw_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), default="user")
    is_active = db.Column(db.Boolean, default=True)
    is_deleted = db.Column(db.Boolean, default=False)

    email = db.Column(db.String(120))
    nickname = db.Column(db.String(120))
    must_change_password = db.Column(db.Boolean, default=False)
    pref_num_questions = db.Column(db.Integer)
    pref_time_per_q = db.Column(db.Integer)

    last_score = db.Column(db.Integer)  # ✅ NEW
    last_total = db.Column(db.Integer)


    play_count = db.Column(db.Integer, default=0)  # 👈 THÊM





class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip = db.Column(db.String(50))
    status = db.Column(db.String(30))  # success / blocked / failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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

    # ✅ Giữ lại topic_id (nullable) để các đoạn code cũ không crash
    topic_id = db.Column(db.Integer, db.ForeignKey("topic.id"), nullable=True)
    topic = db.relationship("Topic")

    # ✅ Hệ folder mới
    folder_id = db.Column(db.Integer, db.ForeignKey("folder.id"), nullable=True)
    folder = db.relationship("Folder")

    text = db.Column(db.Text, nullable=False)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)

    # level: 1/2/3
    level = db.Column(db.Integer, nullable=False, default=1)

    # folder cha
    parent_id = db.Column(db.Integer, db.ForeignKey("folder.id"), nullable=True)
    parent = db.relationship("Folder", remote_side=[id], backref=db.backref("children", lazy=True))

    order_index = db.Column(db.Integer, nullable=False)  # 👈 THÊM
    image = db.Column(db.String(255))  # tên file ảnh




class Choice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, default=False)

    question = db.relationship("Question", backref=db.backref("choices", lazy=True))

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
    attempt_id = db.Column(db.Integer, db.ForeignKey("attempt.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    chosen_choice_id = db.Column(db.Integer, db.ForeignKey("choice.id"), nullable=True)
    is_correct = db.Column(db.Boolean, default=False)

    # ✅ NEW: đánh dấu đã xử lý câu hỏi hay chưa
    answered = db.Column(db.Boolean, default=False)

    attempt = db.relationship("Attempt", backref=db.backref("answers", lazy=True))
    question = db.relationship("Question")
    chosen_choice = db.relationship("Choice")


# ===================== AUTH =====================
@app.context_processor
def inject_year():
    return {"current_year": datetime.now().year}

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required():
    if not current_user.is_authenticated:
        abort(401)
    if current_user.username != "nhoctotokute93":
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
        return redirect(url_for("sets"))

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

        # Tạo user (đúng tên cột pw_hash)
        u = User(
            username=username,
            email=email,
            pw_hash=generate_password_hash(password),
            role="user"
        )

        try:
            db.session.add(u)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("❌ Tên đăng nhập đã tồn tại. Hãy chọn tên khác.")
            return redirect(url_for("register"))

        flash("✅ Tạo tài khoản thành công! Hãy đăng nhập.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        ip = request.remote_addr

        u = User.query.filter_by(username=username).first()

        # ❌ Sai tài khoản hoặc mật khẩu
        if not u or not check_password_hash(u.pw_hash, password):
            db.session.add(LoginLog(
                username=username,
                ip=ip,
                status="failed"
            ))
            db.session.commit()

            flash("Sai tài khoản hoặc mật khẩu")
            return redirect(url_for("login"))

        # ⛔ USER BỊ KHOÁ
        if not u.is_active:
            db.session.add(LoginLog(
                username=u.username,
                ip=ip,
                status="blocked"
            ))
            db.session.commit()

            flash("⛔ Tài khoản đã bị khoá.", "danger")
            return redirect(url_for("login"))

        # ⛔ BỊ CHẶN QUYỀN TRUY CẬP
        if not check_access_permission(u):
            db.session.add(LoginLog(
                username=u.username,
                ip=ip,
                status="blocked"
            ))
            db.session.commit()

            flash("⛔ Tài khoản của bạn chưa được cấp quyền truy cập.", "danger")
            return redirect(url_for("login"))

        # ✅ TỚI ĐÂY MỚI LOGIN
        login_user(u)

        # 🔁 BẮT ĐỔI MẬT KHẨU
        if u.must_change_password:
            db.session.add(LoginLog(
                username=u.username,
                ip=ip,
                status="success"
            ))
            db.session.commit()

            flash("🔐 Vui lòng đổi mật khẩu mới để tiếp tục sử dụng.", "warning")
            return redirect(url_for("account"))

        # ✅ ĐĂNG NHẬP THÀNH CÔNG
        db.session.add(LoginLog(
            username=u.username,
            ip=ip,
            status="success"
        ))
        db.session.commit()

        return redirect(url_for("sets"))

    return render_template("login.html")


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

    content = f"""
HỆ THỐNG ÔN TẬP TAEKWONDO
Được sáng tạo bởi Nguyễn Thiên Phụng

Xin chào,{user.username}!

Xin cảm ơn vì đã tin tưởng và sử dụng hệ thống ôn tập Taekwondo. Xin chúc các bạn có những buổi ôn tập thật thú vị.

Thông tin đăng nhập của bạn:
User: {user.username}
Mật khẩu mới: {new_pass}

Lưu ý: Đây là tin nhắn hệ thống, vui lòng không trả lời email này.
Xin cảm ơn!
"""

    send_email(
        to_email=email,
        subject="Khôi phục mật khẩu – Hệ Thống Ôn Tập Taekwondo",
        body=content
    )

    flash("✅ Vui lòng kiểm tra email để nhận lại thông tin đăng nhập.", "success")
    return redirect(url_for("login"))


@app.route("/account/change-email", methods=["POST"])
@login_required
def change_email():
    email = request.form.get("email", "").strip().lower()

    if not is_valid_email(email):
        flash("❌ Email không hợp lệ.", "danger_email")
        return redirect(url_for("account"))

    if User.query.filter_by(email=email).first():
        flash("❌ Email đã được sử dụng.", "danger_email")
        return redirect(url_for("account"))

    current_user.email = email
    db.session.commit()

    flash("✅ Đổi email thành công!", "success_email")
    return redirect(url_for("account"))


# ===================== PAGES =====================

@app.route("/")
def home():
    return redirect(url_for("sets"))


@app.route("/sets")
@login_required
def sets():
    folder1_list = Folder.query.filter_by(level=1)\
        .order_by(Folder.order_index).all()

    items = []
    for f in folder1_list:
        items.append({
            "name": f.name,
            "image": url_for("static", filename=f.image) if f.image else None,
            "url": url_for("view_set", folder1_id=f.id)
        })

    breadcrumbs = [
        {"name": "Trang chủ", "url": None}
    ]

    return render_template(
        "folder_list.html",
        page_title="Trang chủ",
        items=items,
        breadcrumbs=breadcrumbs
    )


@app.route("/set/<int:folder1_id>", defaults={"folder2_id": None})
@app.route("/set/<int:folder1_id>/<int:folder2_id>")
@login_required
def view_set(folder1_id, folder2_id):

    f1 = Folder.query.get_or_404(folder1_id)

    # ===== FOLDER 2 =====
    if folder2_id is None:
        folder2_list = Folder.query.filter_by(
            level=2, parent_id=folder1_id
        ).order_by(Folder.order_index).all()

        items = []
        for f in folder2_list:
            items.append({
                "name": f.name,
                "image": url_for("static", filename=f.image) if f.image else None,
                "url": url_for("view_set",
                               folder1_id=folder1_id,
                               folder2_id=f.id)
            })

        breadcrumbs = [
            {"name": "Trang chủ", "url": url_for("sets")},
            {"name": f1.name, "url": None}
        ]


        return render_template(
            "folder_list.html",
            page_title=f1.name,
            items=items,
            breadcrumbs=breadcrumbs
        )

    # ===== FOLDER 3 =====
    f2 = Folder.query.get_or_404(folder2_id)

    folder3_list = Folder.query.filter_by(
        level=3, parent_id=folder2_id
    ).order_by(Folder.order_index).all()

    items = []
    for f3 in folder3_list:
        items.append({
            "name": f3.name,
            "image": url_for("static", filename=f3.image) if f3.image else None,
            "url": url_for("quiz_prepare", folder3_id=f3.id)

        })

    breadcrumbs = [
        {"name": "Trang chủ", "url": url_for("sets")},
        {"name": f1.name, "url": url_for("view_set", folder1_id=f1.id)},
        {"name": f2.name, "url": None}
    ]


    return render_template(
        "folder_list.html",
        page_title=f2.name,
        items=items,
        breadcrumbs=breadcrumbs
    )



@app.route("/quiz/prepare/<int:folder3_id>")
@login_required
def quiz_prepare(folder3_id):
    f3 = Folder.query.get_or_404(folder3_id)

    return render_template(
        "quiz_prepare.html",
        topic_name=f3.name,
        start_url=url_for("quiz_start_folder", folder3_id=f3.id)
    )



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

    # ===== LẤY SETTING USER (KHÔNG ÉP) =====
    num_questions = current_user.pref_num_questions   # None = làm hết
    time_per_q = current_user.pref_time_per_q         # None = không tính giờ

    # ===== LẤY CÂU HỎI =====
    qs = Question.query.filter_by(folder_id=folder3_id).all()
    if not qs:
        flash("Chủ đề này chưa có câu hỏi. Vào Admin để tạo câu hỏi trước.", "danger")
        folder1_id = None
        if f3.parent and f3.parent.parent:
            folder1_id = f3.parent.parent.id

        return redirect(url_for("view_set", folder1_id=folder1_id))

    random.shuffle(qs)

    # ===== CHỌN CÂU THEO SETTING =====
    if num_questions is None:
        chosen_qs = qs                    # ✅ làm hết
        final_count = len(qs)
    else:
        n = int(num_questions)
        if len(qs) >= n:
            chosen_qs = qs[:n]            # đủ câu
        else:
            chosen_qs = list(qs)
            need = n - len(qs)
            chosen_qs.extend(random.choices(qs, k=need))  # cho phép lặp
        final_count = n

    # ===== TOPIC MẶC ĐỊNH (TRÁNH NULL) =====
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

    # ===== TẠO ATTEMPT =====
    attempt = Attempt(
        user_id=current_user.id,
        topic_id=default_topic.id,
        created_at=datetime.now(timezone.utc),
        finished_at=None,
        question_count=final_count,
        time_per_q=time_per_q      # ✅ None giữ nguyên
    )
    db.session.add(attempt)
    db.session.commit()

    # ===== GẮN CÂU HỎI =====
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

    # đã làm xong -> qua kết quả
    if attempt.finished_at:
        return redirect(url_for("quiz_result", attempt_id=attempt.id))

    # tìm câu chưa trả lời đầu tiên
    unanswered = AttemptAnswer.query.filter_by(attempt_id=attempt.id, answered=False).first()

    # nếu hết câu -> chấm xong
    if not unanswered:
        attempt.finished_at = datetime.utcnow()
        db.session.commit()
        return redirect(url_for("quiz_result", attempt_id=attempt.id))

    q = db.session.get(Question, unanswered.question_id)

    if request.method == "POST":
        chosen_id = request.form.get("choice_id")
        is_timeout = request.form.get("timeout") == "1"

        # ===== TRƯỜNG HỢP KHÔNG CHỌN GÌ =====
        if not chosen_id:
            unanswered.answered = True
            unanswered.chosen_choice_id = None
            unanswered.is_correct = False
            db.session.commit()
            return redirect(url_for("quiz_do", attempt_id=attempt.id))

        # ===== CÓ CHỌN (BẤM TIẾP HOẶC HẾT GIỜ) =====
        chosen = db.session.get(Choice, int(chosen_id))
        if not chosen or chosen.question_id != q.id:
            return "Đáp án không hợp lệ", 400

        unanswered.answered = True
        unanswered.chosen_choice_id = chosen.id
        unanswered.is_correct = bool(chosen.is_correct)

        db.session.commit()
        return redirect(url_for("quiz_do", attempt_id=attempt.id))

    # progress
    total = AttemptAnswer.query.filter_by(attempt_id=attempt.id).count()
    done = AttemptAnswer.query.filter_by(attempt_id=attempt.id, answered=True).count()

    return render_template(
        "quiz.html",
        attempt=attempt,
        question=q,
        progress=(done, total),
        time_per_q=attempt.time_per_q
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

    # ✅ LƯU ĐIỂM CUỐI + ĐẾM SỐ LẦN CHƠI (CHỈ 1 LẦN – CHỐNG F5)
    if (
        current_user.last_score != score
        or current_user.last_total != total
    ):
        current_user.last_score = score
        current_user.last_total = total

        # 🔥 TĂNG SỐ LẦN CHƠI
        current_user.play_count = (current_user.play_count or 0) + 1

        db.session.commit()

    # ===== REVIEW DATA =====
    review = []
    first_question = None

    for a in answers:
        q = db.session.get(Question, a.question_id)
        if not first_question:
            first_question = q

        correct = Choice.query.filter_by(
            question_id=q.id,
            is_correct=True
        ).first()

        chosen = (
            db.session.get(Choice, a.chosen_choice_id)
            if a.chosen_choice_id
            else None
        )

        review.append((q, chosen, correct, a.is_correct))

    # ===== SUY RA CHỦ ĐỀ (FOLDER 3) =====
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
        replay_url=url_for(
            "quiz_start_folder",
            folder3_id=folder3.id
        ) if folder3 else url_for("sets")
    )


@app.route("/admin/access", methods=["GET", "POST"])
@login_required
def admin_access():
    admin_required()

    setting = AccessSetting.query.first()
    if not setting:
        setting = AccessSetting(mode="all")
        db.session.add(setting)
        db.session.commit()

    if request.method == "POST":
        mode = request.form.get("mode")
        setting.mode = mode

        # reset custom allow
        AccessAllow.query.delete()

        if mode == "custom":
            AccessAllow.query.delete()

            # ✅ ÉP ADMIN VÀO DANH SÁCH
            admins = User.query.filter_by(role="admin").all()
            for a in admins:
                db.session.add(AccessAllow(user_id=a.id))

            # user thường được chọn
            user_ids = request.form.getlist("allowed_users")
            for uid in user_ids:
                db.session.add(AccessAllow(user_id=int(uid)))

        db.session.commit()
        flash("✅ Đã lưu cài đặt truy cập!", "success")
        return redirect(url_for("admin_access"))

    # ===== GET DATA =====
    all_users = User.query.order_by(User.username.asc()).all()

    # user được phép theo DB
    allowed_ids = {a.user_id for a in AccessAllow.query.all()}

    # ⚠️ CHỈ THÊM ADMIN KHI HIỂN THỊ (KHÔNG LƯU DB)
    admin_ids = {u.id for u in all_users if u.role == "admin"}
    display_allowed_ids = allowed_ids.union(admin_ids)

    return render_template(
        "admin_access.html",
        mode=setting.mode,
        users=all_users,
        allowed_ids=display_allowed_ids
    )




@app.route("/admin/logs")
@login_required
def admin_logs():
    admin_required()

    logs = LoginLog.query.order_by(LoginLog.id.desc()).limit(300).all()

    return render_template(
        "admin_logs.html",
        logs=logs
    )

@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def admin_users():
    admin_required()

    if request.method == "POST":
        uid = request.form.get("user_id", type=int)
        action = request.form.get("action")

        if not uid or not action:
            flash("❌ Dữ liệu không hợp lệ.", "danger")
            return redirect(url_for("admin_users"))

        u = User.query.filter_by(id=uid, is_deleted=False).first_or_404()

        # ❌ Không thao tác với chính mình
        if u.id == current_user.id:
            flash("❌ Không thể thao tác với chính tài khoản đang đăng nhập.", "danger")
            return redirect(url_for("admin_users"))

        # ❌ Không xoá admin gốc
        if action == "delete" and u.username == "nhoctotokute93":
            flash("❌ Không thể xoá tài khoản ADMIN hệ thống.", "danger")
            return redirect(url_for("admin_users"))

        # ❌ Không xoá admin cuối cùng
        if action == "delete" and u.role == "admin":
            admin_count = User.query.filter_by(
                role="admin",
                is_deleted=False
            ).count()
            if admin_count <= 1:
                flash("❌ Không thể xoá admin cuối cùng.", "danger")
                return redirect(url_for("admin_users"))

        # ===== ACTIONS =====
        if action == "toggle_active":
            u.is_active = not u.is_active
            db.session.commit()
            flash("🔒 Đã cập nhật trạng thái tài khoản.", "success")

        elif action == "toggle_role":
            u.role = "admin" if u.role == "user" else "user"
            db.session.commit()
            flash("🔁 Đã đổi role người dùng.", "success")

        elif action == "delete":
            # ✅ SOFT DELETE
            u.is_deleted = True
            u.is_active = False

            # 🔥 XOÁ QUYỀN TRUY CẬP LIÊN QUAN
            AccessAllow.query.filter_by(user_id=u.id).delete()

            db.session.commit()
            flash(f"🗑️ Đã xoá user {u.username}", "success")

        return redirect(url_for("admin_users"))

    # ===== ADMIN LIST =====
    admins = (
        User.query
        .filter_by(role="admin", is_deleted=False)
        .order_by(User.username.asc())
        .all()
    )

    # ===== USER LIST =====
    users = (
        User.query
        .filter(
            User.role == "user",
            User.is_deleted == False
        )
        .order_by(
            User.is_active.desc(),
            (User.last_score * 1.0 / db.func.nullif(User.last_total, 0)).desc(),
            User.play_count.asc()
        )
        .all()
    )

    return render_template(
        "admin_users.html",
        admins=admins,
        users=users
    )


# ===================== ADMIN: LIST / EDIT / DELETE =====================
@app.route("/admin/questions", methods=["GET", "POST"])
@login_required
def admin_questions():
    admin_required()

    # ===== POST: thêm câu hỏi =====
    if request.method == "POST":
        folder3_id = request.form.get("folder3_id", type=int)
        q_text = (request.form.get("question_text") or "").strip()
        c1 = (request.form.get("choice1") or "").strip()
        c2 = (request.form.get("choice2") or "").strip()
        c3 = (request.form.get("choice3") or "").strip()
        c4 = (request.form.get("choice4") or "").strip()
        correct = request.form.get("correct")   # "A" / "B" / "C" / "D"

        # ===== VALIDATE =====
        if not folder3_id:
            flash("⚠️ Vui lòng chọn đủ Chủ đề 1 – 2 – 3 trước khi thêm câu hỏi.", "danger")
            return redirect(url_for("admin_questions"))

        if not q_text:
            flash("Vui lòng nhập câu hỏi.", "danger")
            return redirect(url_for("admin_questions", folder3_id=folder3_id))

        if not all([c1, c2, c3, c4]):
            flash("Vui lòng nhập đủ 4 đáp án.", "danger")
            return redirect(url_for("admin_questions", folder3_id=folder3_id))

        if correct not in ("A", "B", "C", "D"):
            flash("Vui lòng chọn đáp án đúng", "danger")
            return redirect(url_for("admin_questions", folder3_id=folder3_id))
            
        # ===== SAVE QUESTION =====
        q = Question(folder_id=folder3_id, text=q_text)
        db.session.add(q)
        db.session.commit()

        # ===== SAVE CHOICES (FIX ĐÚNG LOGIC) =====
        # ✅ MAP CHỮ → SỐ (QUAN TRỌNG)
        correct_map = {
            "A": 1,
            "B": 2,
            "C": 3,
            "D": 4
        }
        correct_index = correct_map[correct]

        for i, txt in enumerate([c1, c2, c3, c4], start=1):
            db.session.add(
                Choice(
                    question_id=q.id,
                    text=txt,
                    is_correct=(i == correct_index)  # ✅ ĐÚNG
                )
            )

        db.session.commit()

        # ===== SUY RA FOLDER CHA =====
        f3 = Folder.query.get(folder3_id)
        folder2_id = f3.parent_id if f3 else None
        folder1_id = f3.parent.parent_id if f3 and f3.parent else None

        flash("✅ Đã thêm câu hỏi.", "success")
        return redirect(
            url_for(
                "admin_questions",
                folder1_id=folder1_id,
                folder2_id=folder2_id,
                folder3_id=folder3_id,
            )
        )

    # ===== GET: LOAD FOLDER =====
    folder1_id = request.args.get("folder1_id", type=int)
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    folder1_list = Folder.query.filter_by(level=1).order_by(Folder.order_index.asc()).all()
    if not folder1_id and folder1_list:
        folder1_id = folder1_list[0].id

    folder2_list = Folder.query.filter_by(
        level=2, parent_id=folder1_id
    ).order_by(Folder.order_index.asc()).all()
    if not folder2_id and folder2_list:
        folder2_id = folder2_list[0].id

    folder3_list = Folder.query.filter_by(
        level=3, parent_id=folder2_id
    ).order_by(Folder.order_index.asc()).all()
    if not folder3_id and folder3_list:
        folder3_id = folder3_list[0].id

    selected_folder1 = Folder.query.get(folder1_id) if folder1_id else None
    selected_folder2 = Folder.query.get(folder2_id) if folder2_id else None
    selected_folder3 = Folder.query.get(folder3_id) if folder3_id else None

    questions = (
        Question.query
        .filter_by(folder_id=folder3_id)
        .order_by(Question.id.desc())
        .all()
        if folder3_id else []
    )

    return render_template(
        "admin_questions.html",
        folder1_list=folder1_list,
        folder2_list=folder2_list,
        folder3_list=folder3_list,
        selected_folder1=selected_folder1,
        selected_folder2=selected_folder2,
        selected_folder3=selected_folder3,
        questions=questions,
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

    new_order = max_order + 1



    # =========================
    # 1️⃣ TẠO FOLDER TRƯỚC
    # =========================
    f = Folder(
        name=name,
        level=level,
        parent_id=parent_id,
        order_index=new_order,
        image=None
    )
    db.session.add(f)
    db.session.commit()   # ⚠️ BẮT BUỘC để có f.id

    # =========================
    # 2️⃣ XỬ LÝ ẢNH SAU
    # =========================
    image = request.files.get("image")
    if image and image.filename:
        f.image = save_folder_image(image, f.level, f.name)
        db.session.commit()


    flash("✅ Đã thêm.", "success")

    if level == 1:
        return redirect(url_for("admin_questions", folder1_id=f.id))
    if level == 2:
        return redirect(url_for("admin_questions", folder1_id=parent_id, folder2_id=f.id))
    return redirect(url_for(
        "admin_questions",
        folder1_id=folder1_id,
        folder2_id=parent_id,
        folder3_id=f.id
    ))



@app.route("/admin/folder/<int:folder_id>/edit", methods=["POST"])
@login_required
def admin_folder_edit(folder_id):
    admin_required()

    f = Folder.query.get_or_404(folder_id)

    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Tên không được trống.", "danger")
        return redirect(request.referrer or url_for("admin_questions"))

    f.name = name

    image = request.files.get("image")
    if image and image.filename:
        f.image = save_folder_image(image, f.level, f.name)

    old_image = f.image
    old_name = slugify(f.name)

    # nếu đổi tên + không upload ảnh mới → đổi tên file
    if old_image and not image:
        old_path = os.path.join(app.static_folder, old_image)
        ext = os.path.splitext(old_path)[1]
        new_filename = f"{slugify(name)}{ext}"
        new_rel_path = f"uploads/folder{f.level}/{new_filename}"
        new_path = os.path.join(app.static_folder, new_rel_path)

        if os.path.exists(old_path) and old_path != new_path:
            os.rename(old_path, new_path)
            f.image = new_rel_path

    db.session.commit()

    flash("✅ Đã cập nhật.", "success")

    folder1_id = request.args.get("folder1_id", type=int)
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    return redirect(url_for(
        "admin_questions",
        folder1_id=folder1_id,
        folder2_id=folder2_id,
        folder3_id=folder3_id
    ))


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




@app.route("/admin/question/<int:question_id>/edit", methods=["GET", "POST"])
@login_required
def admin_edit_question(question_id):
    admin_required()

    q = db.session.get(Question, question_id)
    if not q:
        return "Không tìm thấy câu hỏi", 404

    # Lấy topic an toàn (tránh None)
    topic = getattr(q, "topic", None)
    # Nếu q.topic_id có mà relationship không load được (hoặc topic đã bị xoá) thì cố lấy lại
    if topic is None and getattr(q, "topic_id", None):
        topic = db.session.get(Topic, q.topic_id)

    choices = Choice.query.filter_by(question_id=q.id).order_by(Choice.id.asc()).all()

    # đảm bảo có 4 choices
    if len(choices) != 4:
        AttemptAnswer.query.filter_by(question_id=q.id).delete()
        Choice.query.filter_by(question_id=q.id).delete()
        db.session.commit()

        for txt in ["A", "B", "C", "D"]:
            db.session.add(Choice(question_id=q.id, text=f"Đáp án {txt}", is_correct=False))
        db.session.commit()
        choices = Choice.query.filter_by(question_id=q.id).order_by(Choice.id.asc()).all()

    if request.method == "POST":
        q_text = request.form.get("question_text", "").strip()
        a = request.form.get("a", "").strip()
        b = request.form.get("b", "").strip()
        c = request.form.get("c", "").strip()
        d = request.form.get("d", "").strip()
        correct = request.form.get("correct", "").strip()  # "A"/"B"/"C"/"D"

        if not q_text or not all([a, b, c, d]) or correct not in ["A", "B", "C", "D"]:
            flash("Thiếu dữ liệu. Nhập câu hỏi + 4 đáp án + chọn đáp án đúng.")
            return redirect(url_for("admin_edit_question", question_id=q.id))

        q.text = q_text

        mapping = [("A", a), ("B", b), ("C", c), ("D", d)]
        for i, (key, text_val) in enumerate(mapping):
            choices[i].text = text_val
            choices[i].is_correct = (key == correct)

        db.session.commit()
        flash("✅ Đã cập nhật câu hỏi!")

        # Quay về danh sách: ưu tiên theo folder_id (đúng với màn admin/questions của Ken)
        folder_id = getattr(q, "folder_id", None)
        folder3_id = q.folder_id
        f3 = Folder.query.get(folder3_id)
        folder2_id = f3.parent_id if f3 else None
        folder1_id = f3.parent.parent_id if f3 and f3.parent else None

        return redirect(url_for(
            "admin_questions",
            folder1_id=folder1_id,
            folder2_id=folder2_id,
            folder3_id=folder3_id
        ))

        # Nếu không có folder_id thì quay về chung (hoặc theo topic nếu có)
        if topic:
            return redirect(url_for("admin_questions", topic_id=topic.id))
        return redirect(url_for("admin_questions"))

    # xác định correct hiện tại
    correct_key = "A"
    for i, ch in enumerate(choices):
        if ch.is_correct:
            correct_key = ["A", "B", "C", "D"][i]
            break

    return render_template(
        "admin_edit.html",
        q=q,
        topic=topic,
        choices=choices,
        correct_key=correct_key
    )



@app.route("/admin/question/<int:question_id>/delete", methods=["POST"])
@login_required
def admin_delete_question(question_id):
    admin_required()

    q = db.session.get(Question, question_id)
    if not q:
        flash("Không tìm thấy câu hỏi.")
        return redirect(url_for("admin_questions"))

    folder3_id = q.folder_id

    AttemptAnswer.query.filter_by(question_id=q.id).delete()
    Choice.query.filter_by(question_id=q.id).delete()
    db.session.delete(q)
    db.session.commit()

    flash("🗑️ Đã xoá câu hỏi!")
    f3 = Folder.query.get(folder3_id)
    folder2_id = f3.parent_id if f3 else None
    folder1_id = f3.parent.parent_id if f3 and f3.parent else None

    return redirect(url_for(
        "admin_questions",
        folder1_id=folder1_id,
        folder2_id=folder2_id,
        folder3_id=folder3_id
    ))

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

def send_email(to_email, subject, body):
    sender = "silentnight1993pro@gmail.com"
    app_password = "ptfputiolqmdcmak"  # ⚠️ đổi thành App Password thật

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender, app_password)
        server.send_message(msg)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_schema()
        ensure_user_pref_columns()
        seed_admin()
    app.run(debug=True, use_reloader=False)



