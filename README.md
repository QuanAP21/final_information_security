# CSRF Demo: Vulnerable + Protected

## Project structure

```txt
csrf-demo-complete/
├── package.json
├── README.md
├── bank/
│   ├── server.js
│   ├── data/
│   │   └── db.js
│   ├── public/
│   │   └── styles.css
│   └── views/
│       ├── login.ejs
│       ├── dashboard.ejs
│       └── result.ejs
└── attacker/
    ├── server.js
    └── public/
        ├── index.html
        ├── vulnerable.html
        ├── protected.html
        └── styles.css
```

## Install

```bash
npm install
```

## Run

Terminal 1:

```bash
npm run bank
```

Terminal 2:

```bash
npm run attacker
```

## URLs

- Bank: http://localhost:3000
- Attacker: http://localhost:4000

## Demo accounts

- alice / 123456
- bob / 123456
- mallory / 123456

## Demo flow

### 1) Vulnerable mode
1. Login as `alice`.
2. Stay in **Vulnerable Mode**.
3. Open `http://localhost:4000/vulnerable.html`.
4. Return to Bank and refresh.
5. Alice loses $200 and Mallory gains $200.
6. Transfer history shows forged request status: `SUCCESS (No CSRF Protection)`.

### 2) Protected mode
1. Click **Reset Demo**.
2. Switch to **Protected Mode**.
3. Open `http://localhost:4000/protected.html`.
4. Return to Bank and refresh.
5. Balance stays the same.
6. Transfer history shows forged request status: `BLOCKED (Invalid CSRF Token)`.

## Notes

- This demo uses in-memory data for simplicity.
- `/transfer` is intentionally vulnerable.
- `/secure-transfer` validates `csrfToken` against the token stored in the user session.