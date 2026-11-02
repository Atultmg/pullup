# pullup

QR-based class attendance system. The teacher starts a class and shows a big QR code — students scan it with their phones to check in. No calling names, no paper sheets.

**Live demo:** https://atultmg.pythonanywhere.com

## How it works
- Teacher registers with a teacher code and starts a class — the board shows a big QR code (the link is time-limited)
- Students register once, then scan the QR to check in
- Check in within the late window (default 10 minutes) = **Present**, after that = **Late**
- Optional "in the class" check: students on the class Wi-Fi pass automatically — anyone else shows on the teacher's board as *Waiting for approval*
- Teacher ends the class and gets a report with present/late lists and a CSV download

## Built with
- Python + Flask
- SQLite
- HTML/CSS (custom design, no framework)
- Hosted on PythonAnywhere

## Run it locally
1. `pip install flask qrcode`
2. Set your own SECRET_KEY and TEACHER_CODE at the top of app.py
3. `python3 app.py` — then open http://127.0.0.1:5001
