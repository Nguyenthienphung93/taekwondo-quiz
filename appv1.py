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

def save_folder_image(file, level, folder_id):
    """
    level: 1 | 2 | 3
    folder_id: id của folder vừa tạo
    return: path lưu DB dạng uploads/folderX/filename.jpg
    """
    if not file or file.filename == "":
        return None

    ext = os.path.splitext(file.filename)[1].lower()
    filename = f"f{level}_{folder_id}{ext}"

    sub_dir = f"folder{level}"
    upload_dir = os.path.join(app.static_folder, "uploads", sub_dir)
    os.makedirs(upload_dir, exist_ok=True)

    save_path = os.path.join(upload_dir, filename)
    file.save(save_path)

    # ✅ CHUẨN DUY NHẤT LƯU DB
    return f"uploads/{sub_dir}/{filename}"


UPLOAD_FOLDER = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)




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
    with app.app_context():
        try:
            cols = [r[1] for r in db.session.execute(
                db.text("PRAGMA table_info(user)")
            ).all()]

            if "pref_num_questions" not in cols:
                db.session.execute(
                    db.text("ALTER TABLE user ADD COLUMN pref_num_questions INTEGER")
                )

            if "pref_time_per_q" not in cols:
                db.session.execute(
                    db.text("ALTER TABLE user ADD COLUMN pref_time_per_q INTEGER")
                )

            # ✅ thêm nickname
            if "nickname" not in cols:
                db.session.execute(
                    db.text("ALTER TABLE user ADD COLUMN nickname VARCHAR(120)")
                )

            # ✅ thêm email (cho DB cũ)
            if "email" not in cols:
                db.session.execute(
                    db.text("ALTER TABLE user ADD COLUMN email VARCHAR(120)")
                )

            # ✅ bắt đổi mật khẩu
            if "must_change_password" not in cols:
                db.session.execute(
                    db.text(
                        "ALTER TABLE user "
                        "ADD COLUMN must_change_password BOOLEAN DEFAULT 0"
                    )
                )

            # ✅ C2 – khoá / mở user
            if "is_active" not in cols:
                db.session.execute(
                    db.text(
                        "ALTER TABLE user "
                        "ADD COLUMN is_active BOOLEAN DEFAULT 1"
                    )
                )

            # ✅ soft delete user
            if "is_deleted" not in cols:
                db.session.execute(
                    db.text(
                        "ALTER TABLE user "
                        "ADD COLUMN is_deleted BOOLEAN DEFAULT 0"
                    )
                )


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
    """Tự nâng cấp schema SQLite nếu DB cũ thiếu cột"""
    db_path = os.path.join(app.instance_path, "quiz.db")
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # --- helper: lấy list cột của 1 table ---
    def get_cols(table_name: str):
        cur.execute(f"PRAGMA table_info({table_name})")
        return [r[1] for r in cur.fetchall()]

    # === Bổ sung cột cho bảng question (nếu thiếu) ===
    if "question" in [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
        cols = get_cols("question")

        if "folder_id" not in cols:
            cur.execute("ALTER TABLE question ADD COLUMN folder_id INTEGER")
        if "topic_id" not in cols:
            cur.execute("ALTER TABLE question ADD COLUMN topic_id INTEGER")

    # === Bổ sung cột image cho folder ===
    if "folder" in [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]:
        cols = get_cols("folder")
        if "image" not in cols:
            cur.execute("ALTER TABLE folder ADD COLUMN image VARCHAR(255)")


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
    time_per_q = db.Column(db.Integer, default=15)       # giây

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
    folder1_list = Folder.query.filter_by(level=1).order_by(Folder.id.desc()).all()
    time_per_q = session.get("time_per_q", 15)
    num_questions = session.get("num_questions", 10)
    return render_template("sets.html",
        folder1_list=folder1_list,
        time_per_q=time_per_q,
        num_questions=num_questions
    )


@app.route("/quiz/start/<int:topic_id>")
@login_required
def quiz_start(topic_id):
    # ✅ topic_id lấy từ URL /quiz/start/<int:topic_id> nên chắc chắn có
    topic = Topic.query.get_or_404(topic_id)

    folder1_id = request.args.get("folder1_id", type=int)
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    attempt = Attempt(
        user_id=current_user.id,
        topic_id=topic.id,                 # ✅ không bao giờ None
        created_at=datetime.now(timezone.utc),
        question_count=10,
        time_per_q=5
    )
    db.session.add(attempt)
    db.session.commit()

    return redirect(url_for("quiz_do", attempt_id=attempt.id))


@app.route("/quiz/start_folder/<int:folder3_id>")
@login_required
def quiz_start_folder(folder3_id):
    # folder3 phải tồn tại
    f3 = Folder.query.get_or_404(folder3_id)
    if f3.level != 3:
        return "Folder không hợp lệ (phải là cấp 3).", 400

    # =========================
    # ✅ (E) LẤY SETTING THEO USER
    # None trong DB = NULL (làm hết / không tính giờ)
    # Nếu user chưa set gì => default 10 câu, 10s
    # =========================
    num_questions = current_user.pref_num_questions
    time_per_q = current_user.pref_time_per_q

    # Nếu user chưa set lần nào -> dùng default
    # (lưu ý: vì default của Ken là 10,10 chứ không phải None)
    if current_user.pref_num_questions is None:
        num_questions = DEFAULT_NUM_QUESTIONS  # 10
    if current_user.pref_time_per_q is None:
        time_per_q = DEFAULT_TIME_PER_Q        # 10

    # ✅ lấy câu hỏi theo folder3_id (đúng như admin đang lưu Question.folder_id)
    qs = Question.query.filter_by(folder_id=folder3_id).all()
    if not qs:
        flash("Chủ đề này chưa có câu hỏi. Vào Admin để tạo câu hỏi trước.", "danger")
        return redirect(url_for(
            "view_set",
            folder1_id=(f3.parent.parent.id if f3.parent and f3.parent.parent else f3.id)
        ))

    # ✅ random và chọn số lượng theo setting
    random.shuffle(qs)

    # ✅ chọn câu theo setting
    if num_questions is None:
        # None = làm hết, không lặp
        chosen_qs = qs
        final_count = len(chosen_qs)
    else:
        n = int(num_questions)

        if len(qs) >= n:
            # đủ câu => lấy n câu không lặp
            chosen_qs = qs[:n]
        else:
            # thiếu câu => lấy hết 1 vòng không lặp, rồi bốc thêm cho đủ (cho phép lặp)
            chosen_qs = list(qs)  # 1 vòng đủ tất cả câu
            need = n - len(qs)
            chosen_qs.extend(random.choices(qs, k=need))  # bốc thêm có lặp

        final_count = n


    # ✅ Lấy 1 topic mặc định để tránh lỗi NOT NULL attempt.topic_id
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
        question_count=final_count
,  # ✅ số câu thực tế
        time_per_q=time_per_q           # ✅ None = không tính giờ (F sẽ xử lý ở quiz.html)
    )
    db.session.add(attempt)
    db.session.commit()

    # tạo AttemptAnswer để quiz_do có câu mà chạy
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

        # ✅ HẾT GIỜ / BỎ QUA: không chọn đáp án -> tính sai và qua câu
        if not chosen_id:
            unanswered.answered = True
            unanswered.chosen_choice_id = None
            unanswered.is_correct = False
            db.session.commit()
            return redirect(url_for("quiz_do", attempt_id=attempt.id))

        chosen = db.session.get(Choice, int(chosen_id))
        if not chosen or chosen.question_id != q.id:
            return "Đáp án không hợp lệ", 400

        # ✅ đánh dấu đã trả lời + lưu đúng/sai
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

    # ===== GET =====
    users = (
        User.query
        .filter_by(is_deleted=False)
        .order_by(User.username.asc())
        .all()
    )

    return render_template("admin_users.html", users=users)


# ===================== ADMIN: LIST / EDIT / DELETE =====================
@app.route("/admin/questions", methods=["GET", "POST"])
@login_required
def admin_questions():
    admin_required()

    # ===== POST: thêm câu hỏi (lưu theo folder3_id) =====
    if request.method == "POST":
        folder3_id = request.form.get("folder3_id", type=int)
        q_text = (request.form.get("question_text") or "").strip()
        c1 = (request.form.get("choice1") or "").strip()
        c2 = (request.form.get("choice2") or "").strip()
        c3 = (request.form.get("choice3") or "").strip()
        c4 = (request.form.get("choice4") or "").strip()
        correct = request.form.get("correct", type=int)

        if not folder3_id:
            flash("Thiếu Chủ đề 3 (folder cấp 3).", "danger")
            return redirect(url_for("admin_questions"))
        if not q_text:
            flash("Vui lòng nhập câu hỏi.", "danger")
            return redirect(url_for("admin_questions", folder3_id=folder3_id))
        if not all([c1, c2, c3, c4]):
            flash("Vui lòng nhập đủ 4 đáp án.", "danger")
            return redirect(url_for("admin_questions", folder3_id=folder3_id))
        if correct not in (1, 2, 3, 4):
            flash("Vui lòng chọn đáp án đúng.", "danger")
            return redirect(url_for("admin_questions", folder3_id=folder3_id))

        q = Question(folder_id=folder3_id, text=q_text)
        db.session.add(q)
        db.session.commit()

        for i, txt in enumerate([c1, c2, c3, c4], start=1):
            db.session.add(Choice(question_id=q.id, text=txt, is_correct=(i == correct)))
        db.session.commit()

        flash("✅ Đã thêm câu hỏi.", "success")
        return redirect(url_for("admin_questions", folder3_id=folder3_id))

    # ===== GET: load folder 1/2/3 =====
    folder1_id = request.args.get("folder1_id", type=int)
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    folder1_list = Folder.query.filter_by(level=1).order_by(Folder.id.asc()).all()
    if not folder1_id and folder1_list:
        folder1_id = folder1_list[0].id

    folder2_list = Folder.query.filter_by(level=2, parent_id=folder1_id).order_by(Folder.id.asc()).all() if folder1_id else []
    if not folder2_id and folder2_list:
        folder2_id = folder2_list[0].id

    folder3_list = Folder.query.filter_by(level=3, parent_id=folder2_id).order_by(Folder.id.asc()).all() if folder2_id else []
    if not folder3_id and folder3_list:
        folder3_id = folder3_list[0].id

    selected_folder1 = Folder.query.get(folder1_id) if folder1_id else None
    selected_folder2 = Folder.query.get(folder2_id) if folder2_id else None
    selected_folder3 = Folder.query.get(folder3_id) if folder3_id else None

    questions = Question.query.filter_by(folder_id=folder3_id).order_by(Question.id.desc()).all() if folder3_id else []

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

    # =========================
    # 1️⃣ TẠO FOLDER TRƯỚC
    # =========================
    f = Folder(
        name=name,
        level=level,
        parent_id=parent_id,
        image=None
    )
    db.session.add(f)
    db.session.commit()   # ⚠️ BẮT BUỘC để có f.id

    # =========================
    # 2️⃣ XỬ LÝ ẢNH SAU
    # =========================
    image = request.files.get("image")
    if image and image.filename:
        f.image = save_folder_image(image, level, f.id)
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
        f.image = save_folder_image(image, f.level, f.id)






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
    # 🗑️ XOÁ FILE ẢNH NẾU CÓ
    # =========================
    if f.image:
        image_path = os.path.join(app.static_folder, f.image)
        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except Exception as e:
                print("⚠️ Không xoá được ảnh:", e)

    # =========================
    # 🗑️ XOÁ FOLDER TRONG DB
    # =========================
    db.session.delete(f)
    db.session.commit()

    flash("✅ Đã xoá.", "success")
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
        if folder_id:
            return redirect(url_for("admin_questions", folder3_id=folder_id))

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
    return redirect(url_for("admin_questions", folder3_id=folder3_id))

DEFAULT_NUM_QUESTIONS = 10
DEFAULT_TIME_PER_Q = 10

NUMQ_OPTIONS = [10, 15, 20, 30, 45, 60]   # dropdown
TIME_OPTIONS = [5, 10, 15, 20, 30, 45, 60]  # dropdown


@app.route("/settings", methods=["GET"])
@login_required
def settings():
    # lấy cấu hình hiện tại của user (nếu chưa có thì default)
    cur_num = current_user.pref_num_questions
    cur_time = current_user.pref_time_per_q

    # nếu user chưa từng set gì thì hiển thị mặc định: 10 câu, 10s
    if cur_num is None and current_user.pref_num_questions is None:
        # NOTE: giữ None thật sự nếu Ken muốn default là None,
        # còn yêu cầu Ken là default 10 => ta hiển thị 10
        cur_num_display = DEFAULT_NUM_QUESTIONS
    else:
        cur_num_display = cur_num

    if cur_time is None and current_user.pref_time_per_q is None:
        cur_time_display = DEFAULT_TIME_PER_Q
    else:
        cur_time_display = cur_time

    return render_template(
        "settings.html",
        NUMQ_OPTIONS=NUMQ_OPTIONS,
        TIME_OPTIONS=TIME_OPTIONS,
        cur_num=cur_num_display,
        cur_time=cur_time_display
    )


@app.route("/settings", methods=["POST"])
@login_required
def save_settings():
    num_raw = request.form.get("num_questions")   # "10" hoặc "none"
    time_raw = request.form.get("time_per_q")     # "10" hoặc "none"

    # ✅ parse None
    num_questions = None if num_raw == "none" else int(num_raw)
    time_per_q = None if time_raw == "none" else int(time_raw)

    # ✅ validate (None là hợp lệ)
    if (num_questions is not None) and (num_questions not in NUMQ_OPTIONS):
        num_questions = DEFAULT_NUM_QUESTIONS
    if (time_per_q is not None) and (time_per_q not in TIME_OPTIONS):
        time_per_q = DEFAULT_TIME_PER_Q

    # ✅ lưu vào DB theo user
    current_user.pref_num_questions = num_questions
    current_user.pref_time_per_q = time_per_q
    db.session.commit()

    flash("✅ Đã lưu cài đặt!", "success")
    return redirect(url_for("sets"))




@app.route("/set/<int:folder1_id>")
@login_required
def view_set(folder1_id):
    folder2_id = request.args.get("folder2_id", type=int)
    folder3_id = request.args.get("folder3_id", type=int)

    f1 = Folder.query.get_or_404(folder1_id)
    folder2_list = Folder.query.filter_by(parent_id=f1.id).all()

    selected_folder2 = Folder.query.get(folder2_id) if folder2_id else None
    folder3_list = Folder.query.filter_by(parent_id=selected_folder2.id).all() if selected_folder2 else []
    selected_folder3 = Folder.query.get(folder3_id) if folder3_id else None

    # ✅ kiểm tra folder3 có câu hỏi không để bật nút Start
    qcount = 0
    if selected_folder3:
        qcount = Question.query.filter_by(folder_id=selected_folder3.id).count()

    return render_template(
        "set_detail.html",
        f1=f1,
        folder2_list=folder2_list,
        selected_folder2=selected_folder2,
        folder3_list=folder3_list,
        selected_folder3=selected_folder3,
        qcount=qcount,
    )













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



