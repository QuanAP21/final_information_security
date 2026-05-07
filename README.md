# 🛡️ CSRF Attack Lab — Interactive Security Demo

> **Môn học:** An toàn Thông tin | **Dạng bài:** Demo tấn công & phòng thủ thực chiến  
> **Mục tiêu:** Mô phỏng và phân tích các vector tấn công CSRF, XSS kết hợp CSRF trên ứng dụng ngân hàng giả lập

---

## 📋 Mục lục

- [Tổng quan](#-tổng-quan)
- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống)
- [Cài đặt & Khởi chạy](#-cài-đặt--khởi-chạy)
- [Tài khoản demo](#-tài-khoản-demo)
- [Các mức bảo mật](#-các-mức-bảo-mật)
- [Luồng demo tấn công](#-luồng-demo-tấn-công)
  - [1. External CSRF](#1-external-csrf-tấn-công-csrf-từ-trang-ngoài)
  - [2. Stored XSS + CSRF](#2-stored-xss--csrf)
  - [3. DOM XSS + CSRF (qua postMessage)](#3-dom-xss--csrf-qua-postmessage)
- [Cơ chế phòng thủ](#-cơ-chế-phòng-thủ)
- [Security Dashboard](#-security-dashboard)
- [Cấu trúc dự án](#-cấu-trúc-dự-án)
- [Công nghệ sử dụng](#-công-nghệ-sử-dụng)

---

## 🔍 Tổng quan

Dự án mô phỏng một hệ thống ngân hàng trực tuyến (**SecureBank**) và một trang web tấn công (**Attacker**) chạy song song trên cùng máy. Người dùng có thể tương tác thực tế để quan sát:

- **Khi nào** một tấn công CSRF thành công
- **Tại sao** nó bị chặn khi bật bảo vệ
- **Sự khác biệt** giữa các cấp độ bảo mật Low / Medium / High

### Các vector tấn công được mô phỏng

| Vector | Mô tả |
|---|---|
| **External CSRF** | Trang giả mạo gửi form POST đến bank từ origin khác |
| **Stored XSS + CSRF** | Script độc hại được lưu vào DB, tự thực thi khi nạn nhân mở trang |
| **DOM XSS + CSRF** | Payload được truyền qua `postMessage` từ trang attacker vào bank |
| **Reward-click CSRF** | Nạn nhân bị lừa click vào link "nhận thưởng", kích hoạt forged request |

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────┐       ┌──────────────────────────┐
│      Bank Server            │       │     Attacker Server      │
│   http://localhost:3000     │       │  http://localhost:4000   │
│                             │       │                          │
│  ┌──────────┐  ┌─────────┐  │       │  ┌────────────────────┐  │
│  │  EJS     │  │ Session │  │◄──────│  │  index.html        │  │
│  │  Views   │  │ Store   │  │       │  │  partner-message   │  │
│  └──────────┘  └─────────┘  │       │  │  reward-claim      │  │
│                             │       │  └────────────────────┘  │
│  ┌──────────────────────┐   │       └──────────────────────────┘
│  │ Transfer / CSRF API  │   │
│  │ /transfer            │   │
│  │ /seed-xss-open       │   │
│  │ /arm-dom-xss         │   │
│  │ /attack-status (SSE) │   │
│  └──────────────────────┘   │
└─────────────────────────────┘
```

**Luồng dữ liệu:**
- Bank chạy tại `localhost:3000` — xử lý đăng nhập, chuyển tiền, bình luận, CSP
- Attacker chạy tại `localhost:4000` — phục vụ các trang HTML tấn công tĩnh
- Hai server giao tiếp qua HTTP cross-origin (CORS có kiểm soát cho `/attack-status`)

---

## 🚀 Cài đặt & Khởi chạy

### Yêu cầu hệ thống

- **Node.js** >= 16.x
- **npm** >= 8.x

### Cài đặt

```bash
# Clone hoặc giải nén dự án
cd final_information_security

# Cài đặt dependencies
npm install
```

### Khởi chạy

Mở **hai terminal riêng biệt**:

**Terminal 1 — Bank Server:**
```bash
npm run bank
# → Bank running at http://localhost:3000
```

**Terminal 2 — Attacker Server:**
```bash
npm run attacker
# → Attacker running at http://127.0.0.1:4000
```

### Truy cập

| Service | URL |
|---|---|
| 🏦 SecureBank | http://localhost:3000 |
| 🎯 Attacker | http://localhost:4000 |

> ⚠️ **Lưu ý:** Cả hai server phải chạy đồng thời. Nếu chỉ chạy Bank, các demo tấn công từ Attacker sẽ không hoạt động.

---

## 👤 Tài khoản demo

| Username | Password | Vai trò |
|---|---|---|
| `alice` | `123456` | Nạn nhân (victim) |
| `bob` | `123456` | Người dùng hợp lệ |
| `mallory` | `123456` | Kẻ tấn công (attacker) |

> 💡 Trong các kịch bản demo, **Alice** đóng vai nạn nhân bị lừa, **Mallory** là tài khoản nhận tiền trái phép.

---

## 🔐 Các mức bảo mật

Người dùng có thể chuyển đổi mức bảo mật ngay trên Dashboard:

### 🔴 Low (Mặc định)
- Không có CSRF token
- Cookie không có `SameSite`
- Không kiểm tra `Origin` / `Referer`
- **Tất cả vector tấn công đều thành công**

### 🟡 Medium
- Kiểm tra `Origin` và `Referer` header cho External CSRF
- Có CSRF token trong form (hidden field)
- **External CSRF bị chặn**, nhưng Stored XSS + CSRF **vẫn bypass được** vì script chạy trong-origin

### 🟢 High
- Toàn bộ bảo vệ của Medium
- **Content Security Policy (CSP) nghiêm ngặt** với `nonce` ngẫu nhiên mỗi request
- `script-src 'nonce-{random}'` — block tất cả inline script không có nonce
- `require-trusted-types-for 'script'` — Trusted Types API
- Stored XSS bị **neutralized** trước khi chạy
- DOM XSS bị **chặn** bởi CSP và Trusted Types

### ⚙️ Lab Mode — Cookie SameSite

Cho phép thử nghiệm ảnh hưởng của thuộc tính `SameSite` đối với External CSRF:

| Chế độ | Mô tả | Ảnh hưởng |
|---|---|---|
| `Unset` | Không set SameSite | CSRF dễ thành công |
| `Lax` | Cookie chỉ gửi cho GET top-level | POST-based CSRF bị chặn bởi browser |
| `Strict` | Cookie chỉ gửi same-site | CSRF rất khó thành công |
| `None` | Cho phép cross-site | Cần HTTPS, thường bị reject ở local |

### ⚙️ Lab Mode — Double-Submit Cookie

Kích hoạt cơ chế **Double-Submit Cookie** cho CSRF token:
- Server issue cookie `XSRF-TOKEN` (không `httpOnly`)
- Client phải gửi cả cookie lẫn form field với giá trị khớp nhau
- Attacker không thể đọc cookie từ cross-origin → không thể bypass

---

## 🎬 Luồng demo tấn công

> **Trước mỗi demo:** Nhấn **Reset Demo** để đưa số dư về trạng thái ban đầu.

---

### 1. External CSRF (Tấn công CSRF từ trang ngoài)

**Kịch bản:** Alice đang đăng nhập Bank, đồng thời truy cập một trang "partner" giả mạo. Trang này tự động submit một form ẩn đến Bank, chuyển tiền của Alice sang Mallory mà không cần Alice biết.

#### 🔴 Demo — Khi bị tấn công (Low security)

1. Đăng nhập bằng tài khoản `alice`
2. Đảm bảo đang ở **Security Level: Low**
3. Mở tab mới → truy cập `http://localhost:4000` → chọn **"External CSRF Attack"**
4. Quan sát form ẩn tự submit
5. Quay lại Bank → F5 → Alice mất $200, Mallory nhận $200
6. Transfer history: `External CSRF | SUCCESS | Risk 95/100`

#### 🟡 Demo — Bị chặn (Medium/High security)

1. Trên Dashboard → chuyển sang **Security Level: Medium**
2. Lặp lại bước 3–4
3. Quay lại Bank → số dư **không thay đổi**
4. Transfer history: `External CSRF | BLOCKED | Origin/Referer check failed`

---

### 2. Stored XSS + CSRF

**Kịch bản:** Mallory gửi một "bình luận" chứa `<script>` độc hại vào phần notification của Bank. Khi Alice mở Dashboard, script tự động chạy trong context của Bank, đọc CSRF token từ DOM, và gửi request chuyển tiền.

> **Nguy hiểm:** Vì script chạy từ **cùng origin** với Bank, các biện pháp kiểm tra Origin/Referer và CSRF token thông thường **đều bị bypass**.

#### 🔴 Demo — Thành công (Low / Medium security)

1. Đăng nhập `alice`, đặt **Low** hoặc **Medium**
2. Mở tab mới → `http://localhost:4000` → chọn **"Stored XSS Attack"**
3. Nhấn **"Plant Payload"** — script được inject vào notification feed của Bank
4. Attack Monitor hiển thị: `Status: planted`
5. Quay lại Bank tab → F5 (reload Dashboard)
6. Script kích hoạt ngay lập tức (sau 1 giây)
7. Alice mất $200, Attack Monitor: `Status: succeeded`

#### 🟢 Demo — Bị chặn (High security)

1. Chuyển sang **Security Level: High**
2. Plant payload như trên
3. Reload Dashboard của Alice
4. CSP nonce block script → Attack Monitor: `Status: neutralized`
5. Transfer history: `Stored XSS + CSRF | BLOCKED | Risk 86/100`

---

### 3. DOM XSS + CSRF (qua postMessage)

**Kịch bản:** Bank có tính năng "Partner Reward" — mở một iframe từ trang attacker. Attacker gửi `postMessage` vào Bank với payload JavaScript. Nếu Bank xử lý message không an toàn (`innerHTML`/`eval`), script chạy và thực hiện CSRF.

#### 🔴 Demo — Thành công (Low / Medium security)

1. Đăng nhập `alice`, đặt **Low** hoặc **Medium**
2. Trên Dashboard → nhấn **"View Partner Rewards"**
3. Bank mở trang partner (từ attacker origin)
4. Partner iframe gửi `postMessage` chứa JavaScript payload
5. Bank nhận và inject payload vào DOM không an toàn
6. Script đọc CSRF token và gửi forged transfer
7. Alice mất $200 → Attack Monitor: `Status: succeeded`

#### 🟢 Demo — Bị chặn (High security)

1. Chuyển sang **Security Level: High**
2. Lặp lại các bước trên
3. CSP `require-trusted-types-for 'script'` block `innerHTML` chứa script
4. Attack Monitor: `Status: neutralized`

---

## 🛡️ Cơ chế phòng thủ

### CSRF Token (Synchronizer Token Pattern)
```
Server → tạo token ngẫu nhiên → lưu vào session
Form   → nhúng token vào hidden field
Server → so sánh token trong form với session
Attacker → không thể đọc token từ cross-origin → request bị reject
```

### Double-Submit Cookie
```
Server → issue XSRF-TOKEN cookie (không httpOnly)
Client → đọc cookie → gửi kèm trong form body
Server → verify: cookie == body value == session value
Attacker → không đọc được cookie từ cross-origin
```

### Origin / Referer Validation
```
Server → kiểm tra req.headers.origin hoặc req.headers.referer
Nếu request từ ngoài BANK_ORIGIN → reject 403
```

### Content Security Policy (High mode)
```http
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{random16bytes}';
  script-src-attr 'none';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types bankPolicy;
  frame-ancestors 'self'
```

### SameSite Cookie Attribute
```
SameSite=Lax    → block POST từ cross-site (hầu hết CSRF)
SameSite=Strict → block mọi cross-site request
```

---

## 📊 Security Dashboard

Dashboard cung cấp real-time monitoring:

| Thông số | Mô tả |
|---|---|
| **Total Requests** | Tổng số request ghi nhận |
| **Blocked Events** | Số tấn công bị chặn thành công |
| **Critical Events** | Số tấn công có Risk Score ≥ 95 |
| **Malicious Notifications** | Số comment chứa payload XSS |
| **Latest Insight** | Vector tấn công gần nhất và kết quả |

### Risk Score Matrix

| Trạng thái | Vector | Risk Flag | Score |
|---|---|---|---|
| SUCCESS | External CSRF | 🔴 CRITICAL | 95 |
| SUCCESS | Stored XSS + CSRF | 🔴 CRITICAL | 100 |
| SUCCESS | DOM XSS + CSRF | 🔴 CRITICAL | 100 |
| BLOCKED | Stored XSS + CSRF | 🟠 HIGH | 86 |
| BLOCKED | DOM XSS + CSRF | 🟠 HIGH | 88 |
| BLOCKED | External CSRF | 🟠 HIGH | 78 |
| FAILED | Any | 🟡 MEDIUM | 35 |
| SUCCESS | Legitimate | 🟢 LOW | 8–18 |

---

## 📁 Cấu trúc dự án

```
final_information_security/
├── package.json                  # Dependencies & scripts
├── README.md                     # Tài liệu này
│
├── bank/                         # Server ngân hàng (victim)
│   ├── server.js                 # Express app, API, CSRF logic (1092 lines)
│   ├── data/
│   │   └── db.js                 # In-memory database (users, events, comments)
│   ├── public/
│   │   └── styles.css            # Bank UI styles
│   └── views/                    # EJS templates
│       ├── login.ejs             # Trang đăng nhập
│       ├── dashboard.ejs         # Dashboard chính (transfer, monitor, comments)
│       ├── result.ejs            # Kết quả transfer (success/blocked/error)
│       ├── partner_redirect.ejs  # Trang partner reward (DOM XSS entry)
│       └── partner_dom_lab.ejs   # Lab page cho DOM XSS
│
└── attacker/                     # Server kẻ tấn công
    ├── server.js                 # Express static file server
    └── public/
        ├── index.html            # Hub chọn loại tấn công
        ├── partner-message.html  # postMessage payload cho DOM XSS
        ├── reward-claim.html     # Reward-click CSRF trigger
        └── styles.css            # Attacker UI styles
```

---

## 🔧 Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Runtime | Node.js |
| Web Framework | Express.js 4.x |
| Template Engine | EJS 3.x |
| Session Management | express-session |
| CSRF Token | Node.js `crypto.randomUUID()` |
| CSP Nonce | Node.js `crypto.randomBytes(16)` |
| Storage | In-memory (reset khi restart) |

---

## 📚 Tài liệu tham khảo

- [OWASP — Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [OWASP — Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [MDN — SameSite Cookie Attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [W3C — Trusted Types](https://w3c.github.io/trusted-types/dist/spec/)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

<div align="center">

**🔐 CSRF Attack Lab** — Dự án thực hành môn An toàn Thông tin

*Chỉ sử dụng cho mục đích học tập và nghiên cứu.*

</div>
