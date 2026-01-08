from flask import Flask, request, render_template, redirect, session, jsonify
import sqlite3
import os
import hashlib
import time
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB = "database.db"
UPLOAD_FOLDER = "uploads"
FLAG = "STOREX{burp_can_break_logic_not_crypto}"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    
    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    
    # Products table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            visible INTEGER DEFAULT 1,
            vendor_only INTEGER DEFAULT 0
        )
    """)
    
    # Insert sample data
    cur.execute("DELETE FROM users")
    cur.execute("DELETE FROM products")
    
    # Add users (weak hash for realism but not actual MD5)
    cur.execute("INSERT INTO users VALUES (1, 'admin@storex.com', 'c4ca4238a0b923820dcc509a6f75849b', 'admin')")
    cur.execute("INSERT INTO users VALUES (2, 'vendor@storex.com', '098f6bcd4621d373cade4e832627b4f6', 'vendor')")
    cur.execute("INSERT INTO users VALUES (3, 'user@storex.com', '5f4dcc3b5aa765d61d8327deb882cf99', 'user')")
    
    # Add products
    cur.execute("INSERT INTO products VALUES (1, 'Laptop Pro', 'High-performance laptop', 1, 0)")
    cur.execute("INSERT INTO products VALUES (2, 'Wireless Mouse', 'Ergonomic mouse', 1, 0)")
    cur.execute("INSERT INTO products VALUES (3, 'Secret Vendor Kit', 'Internal use only - Vendor provisioning tools', 0, 1)")
    cur.execute("INSERT INTO products VALUES (4, 'USB Drive', 'Fast storage', 1, 0)")
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

def query_db(query, args=(), one=False):
    """Execute database query"""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    result = cur.execute(query, args).fetchall()
    conn.commit()
    conn.close()
    return (result[0] if result else None) if one else result

# ---------------- AUTHENTICATION ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        
        # Vulnerable SQL Injection point
        # Players need to bypass with: ' OR '1'='1' --
        query = f"SELECT * FROM users WHERE email='{email}' AND password='{password}'"
        
        try:
            result = query_db(query)
            
            if result:
                user = dict(result[0])
                session["auth"] = "partial"
                session["user_id"] = user["id"]
                session["email"] = user["email"]
                session["role"] = user["role"]
                session["stage"] = 1  # Track progression
                
                return redirect("/dashboard")
            
            return render_template("login.html", error="Invalid credentials")
        
        except Exception as e:
            # Don't reveal SQL errors in production, but hint at vulnerability
            return render_template("login.html", error="Database query failed")
    
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if session.get("auth") != "partial":
        return redirect("/")
    
    # Show different content based on progression
    stage = session.get("stage", 1)
    
    return render_template("dashboard.html", stage=stage)

# ---------------- PRODUCTS LIST ----------------
@app.route("/products")
def products():
    if session.get("auth") != "partial":
        return redirect("/")
    
    # Only show visible products
    items = query_db("SELECT id, name FROM products WHERE visible=1")
    return render_template("products.html", items=items)

# ---------------- PRODUCT DETAIL (IDOR) ----------------
@app.route("/product")
def product_detail():
    if session.get("auth") != "partial":
        return redirect("/")
    
    pid = request.args.get("id", "")
    
    if not pid.isdigit():
        return "Invalid product ID", 400
    
    # Vulnerable IDOR - no access control on hidden products
    data = query_db(f"SELECT * FROM products WHERE id={pid}")
    
    hidden_unlocked = False
    
    if data:
        product = dict(data[0])
        
        # Check if this is the vendor-only product (ID 3)
        if product["vendor_only"] == 1:
            session["idor_found"] = True
            session["stage"] = 2
            hidden_unlocked = True
    
    return render_template("product_detail.html", 
                          product=data[0] if data else None,
                          hidden=hidden_unlocked)

# ---------------- FILE UPLOAD ----------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    # Check if IDOR was exploited
    if not session.get("idor_found"):
        return redirect("/dashboard")
    
    if request.method == "POST":
        # Simulate file processing without actually saving
        # This represents internal system sync
        
        # Check if file was provided
        if 'file' not in request.files:
            return "No file provided", 400
        
        file = request.files['file']
        
        if file.filename == '':
            return "No file selected", 400
        
        # Simulate processing delay
        time.sleep(0.5)
        
        # Mark internal sync complete
        session["internal_sync"] = True
        session["stage"] = 3
        
        return redirect("/dashboard")
    
    return render_template("upload.html")

# ---------------- OTP VERIFICATION (Logic Flaw) ----------------
@app.route("/otp", methods=["GET", "POST"])
def otp():
    # Check if internal sync was completed
    if not session.get("internal_sync"):
        return redirect("/dashboard")
    
    if request.method == "POST":
        # CRITICAL LOGIC FLAW:
        # If 'otp' parameter is missing, assume verification bypassed
        # This simulates a common logic error in authentication flows
        
        if "otp" not in request.form:
            # Player found the flaw by removing the parameter
            session["stage"] = 4
            return render_template("success.html", flag=FLAG)
        
        otp = request.form.get("otp", "")
        
        # The OTP is intentionally unguessable
        correct_otp = hashlib.sha256(f"{session['user_id']}{time.time()}".encode()).hexdigest()[:6]
        
        if otp == correct_otp:
            return render_template("success.html", flag=FLAG)
        
        return render_template("otp.html", error="Invalid OTP. Please check your email.")
    
    return render_template("otp.html")

# ---------------- HINT ENDPOINT (Optional) ----------------
@app.route("/api/health")
def health():
    """Hidden endpoint that gives hints about progression"""
    if session.get("auth") != "partial":
        return jsonify({"status": "unauthorized"}), 401
    
    stage = session.get("stage", 1)
    hints = {
        1: "Database queries can be manipulated...",
        2: "Not all products are visible to everyone. Try different IDs.",
        3: "Internal systems trust vendor uploads. What happens after?",
        4: "Sometimes the absence of data is more powerful than its presence."
    }
    
    return jsonify({
        "status": "ok",
        "stage": stage,
        "hint": hints.get(stage, "Keep exploring...")
    })

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(404)
def not_found(e):
    return "Page not found", 404

@app.errorhandler(500)
def server_error(e):
    return "Internal server error", 500

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)