# 🛡️ Real-Time Security Alert and Response System

**A proactive, intelligent security monitoring platform for digital retail, inspired by real-world enterprise needs.  
Built with Django and pure Python for both clarity and rapid prototyping.**

---

## 🚀 Overview

Modern e-commerce and fintech platforms face constant threats—fraud, account takeovers, payment abuse—that cost millions. Most existing systems detect these *after* the damage is done.

This project provides a **real-time, automated security alert and response platform**, featuring:

- **Live activity monitoring**
- **Rule-based and AI-driven threat detection**
- **Instant admin/user notifications**
- **Automated account lockdown and self-service unlock via OTP**
- **Rich dashboards for both users and admins**

---

## 🎯 Features

### 1. **Activity Monitoring**
- Tracks critical user actions: logins, password changes, transactions, failed payments, and browsing.
- Data sources: frontend/backend webhooks, logs, session metadata, and payment events.

### 2. **Threat Detection Engine**
- **Rule-based detection** (e.g., multiple failed logins, large transactions from new devices, suspicious browsing).
- **(Optional)** AI anomaly detection (Isolation Forest, One-Class SVM—see roadmap).
- Each event gets a *severity score* and full context for triage.

### 3. **Real-Time Alerts**
- Admins see a live feed of security alerts (with filter/search).
- Alerts contain: user/session/device, geo-IP, summary, severity, and suggested actions.
- **User-facing alerts:** Users see their own flagged events and can dispute ("This wasn't me!").

### 4. **Automated Response System**
- For high-severity threats:
    - User account is temporarily locked (sensitive actions blocked).
    - User is notified and offered self-service unlock via OTP (simulated or real email/SMS).
    - Admin can override or escalate, all with one click.

### 5. **Security Health and Transparency**
- Every user sees a dynamic “Security Health” bar—higher if their account is clean, lower if alerts exist.
- Users get actionable suggestions (enable 2FA, review recent activity).
- Full transparency: users can see what happened, when, and why.

### 6. **Modern, Minimal Dashboard**
- Responsive home page, member, and admin dashboards (basic Django templates—easy to style for your hackathon!).
- Instant event simulation from the UI (no Postman needed!).
- Admins have instant “resolve” and “unblock” options.

---

## 🛠️ Tech Stack

- **Backend:** Django (API, business logic, admin, ORM)
- **Frontend:** Django Templates (minimal, pure HTML/CSS, ready for customization)
- **Database:** SQLite/PostgreSQL (via Django ORM)
- **Alerting:** Email (console for demo, extendable to SMTP/SMS)
- **Anomaly Detection:** Python (Scikit-learn, PyOD ready for ML integration)
- **Other:** Docker-ready, cross-platform

---

## 📸 Screenshots

> <img width="1896" height="965" alt="image" src="https://github.com/user-attachments/assets/a175778f-f6ac-4992-be49-8a13a6a90b79" />
![login](https://github.com/user-attachments/assets/79d2fe75-2345-4fe3-87e5-120cbcd6a6a2)
> <img width="1882" height="910" alt="image" src="https://github.com/user-attachments/assets/bade1fe4-7626-43f2-8170-a2a31fb31467" />
<img width="1842" height="905" alt="image" src="https://github.com/user-attachments/assets/c1ad8ed8-2211-4e69-be56-e48f6d13b0ab" />
<img width="1868" height="921" alt="image" src="https://github.com/user-attachments/assets/4675a0d6-20a1-4c34-b225-3f035cf36c40" />






---

## 💡 Key Innovations

- **Proactive security:** Alerts + actions happen *before* damage, not after.
- **User empowerment:** End users can self-verify suspicious events via OTP.
- **Business value:** Reduces fraud losses and support costs, boosts customer trust.
- **Hackathon-ready:** Fast, clear UI for demo. All testing via web—no extra tools needed.

---

## ⚡ How It Works (Quick Walkthrough)

1. **Monitor:** Every critical user event is sent to the backend (via form, API, or real app).
2. **Detect:** Rules/ML flag anything suspicious, assigning a severity and full context.
3. **Alert:** Admins get instant alerts in dashboard and (simulated) email; users see flagged events and “This wasn’t me!” button.
4. **Respond:** High-severity? The user is locked out of sensitive actions until they confirm via OTP, or admin reviews/unlocks.
5. **Recover:** User or admin unlocks, health bar rises, account is safe again.

---

## 🚦 Demo/Test Cases

### *No need for Postman! Test everything in the web UI:*
- Trigger a large transaction to see a lock and OTP flow.
- Trigger failed logins, password changes, etc., to see medium/low severity alerts.
- Use "This wasn't me" and unlock actions as both user and admin.

---

## 🔒 Security & Extensibility

- **OTP via email/SMS**: Can be integrated with Twilio, Sendgrid, etc.
- **Role-based access**: Members and admins have totally different views and privileges.
- **Extensible rules:** Add new detection rules in a single place.
- **ML anomaly detection**: Hooks in place for advanced detection.
- **Rate limiting, geo-IP, and blockchain-ready**: Easy to add.

---

## 🏗️ Roadmap

- Add full ML anomaly detection.
- Slack/Telegram alert integration.
- Advanced search/filter on alert feed.
- User-facing notification history.
- Audit log hardening (blockchain or append-only).
- Theme/UI polish.

---

## 🚀 Quickstart

1. **Clone & Install**
    ```bash
    git clone https://github.com/yourusername/security-alert-system.git
    cd security-alert-system
    pip install -r requirements.txt
    ```

2. **Set up DB and Admin**
    ```bash
    python manage.py migrate
    python manage.py createsuperuser
    python manage.py runserver
    ```

3. **Go to:**  
    - `http://localhost:8000/` – Home
    - `http://localhost:8000/login/` – Member/Admin Login
    - `http://localhost:8000/member/` – Member Dashboard (test alerts/events)
    - `http://localhost:8000/admin_dashboard/` – Admin Alert Feed

4. **Simulate events** from the dashboard to see everything in action!

---

## 🤝 Contributing

Pull requests and feature suggestions are always welcome.  
Please open an issue or PR with your ideas or improvements.

---


## 📣 Credits

Created by **Astubh Mishra** for Walmart Hackathon 2025.  
Inspired by real-world threats and a passion for smarter, safer digital commerce.

---

> **For questions or demo requests, feel free to contact or open an issue!**
