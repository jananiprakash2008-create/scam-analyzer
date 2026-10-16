import re
import html
import streamlit as st

st.set_page_config(page_title="Scam Message Analyzer", page_icon="🛡️")
st.title("🛡️ Scam Message Analyzer")
st.caption("Made for Indian students: UPI, KYC, courier, job-offer and Tanglish scams")

RULES = {
    "Urgency / panic": (
        ["urgent", "act now", "blocked", "suspended", "immediately", "last warning",
         "within 24", "expire", "block aagidum", "udane", "seekiram"], 2,
        "Scammers create panic so you act without thinking."),
    "Asks for sensitive info": (
        ["otp", "password", "pin", "cvv", "card number", "send money", "upi pin",
         "otp anuppunga", "paisa anuppunga"], 3,
        "Real banks and apps never ask for OTP, PIN or password."),
    "Impersonation / bait": (
        ["kyc", "sbi", "paytm", "phonepe", "gpay", "hdfc", "icici", "refund", "lottery",
         "prize", "courier", "customs", "electricity bill", "disconnect", "unga account",
         "kyc update pannunga"], 2,
        "Scammers pretend to be trusted brands or offer rewards."),
    "Fake job / money offer": (
        ["work from home", "earn daily", "registration fee", "internship fee",
         "guaranteed job", "easy money"], 3,
        "Real jobs and internships never ask you to pay first."),
}

SHORTENERS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "cutt.ly"]
BAD_END = [".xyz", ".top", ".click", ".buzz"]
OFFICIAL = {"sbi": ["sbi.co.in", "onlinesbi.sbi"], "paytm": ["paytm.com"],
            "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"],
            "amazon": ["amazon.in", "amazon.com"], "paypal": ["paypal.com"],
            "phonepe": ["phonepe.com"], "google": ["google.com"]}

if "msg" not in st.session_state:
    st.session_state.msg = ""

c1, c2, c3 = st.columns(3)
if c1.button("Sample scam"):
    st.session_state.msg = ("Urgent! Your SBI account is blocked. Update KYC at "
                            "http://sbi-kyc-update.xyz and send your OTP now.")
if c2.button("Tanglish scam"):
    st.session_state.msg = ("Unga account block aagidum! KYC update pannunga udane. "
                            "Link: http://bit.ly/kyc123 OTP anuppunga.")
if c3.button("Safe message"):
    st.session_state.msg = "Hi, are we meeting for lunch at 1 pm tomorrow?"

msg = st.text_area("Paste a message", key="msg", height=150)

if st.button("Analyze", type="primary"):
    text = msg.lower()
    score = 0
    marks = []
    findings = []

    for name, (words, pts, why) in RULES.items():
        hits = [w for w in words if w in text]
        if hits:
            score += pts * len(hits)
            marks += hits
            findings.append((f"**{name}**: {', '.join(hits)}", why))

    for u in re.findall(r"(?:https?://|www\.)\S+", text):
        u = u.rstrip(".,!)")
        host = re.sub(r"^https?://", "", u).split("/")[0].split("?")[0]
        reasons = []
        if any(s in host for s in SHORTENERS):
            reasons.append("shortened link hides the real website")
        if any(host.endswith(e) for e in BAD_END):
            reasons.append("unusual domain ending")
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            reasons.append("IP address instead of a website name")
        fixed = host.replace("1", "l").replace("0", "o")
        for brand, real in OFFICIAL.items():
            if brand in fixed and not any(host == r or host.endswith("." + r) for r in real):
                reasons.append(f"looks like '{brand}' but is not its official site")
        if reasons:
            score += 3 * len(reasons)
            marks.append(u)
            findings.append((f"**Suspicious link**: {u}", "; ".join(reasons).capitalize() + "."))

    st.subheader("Your message, flagged")
    safe = html.escape(msg)
    if marks:
        pattern = "|".join(re.escape(html.escape(m)) for m in sorted(set(marks), key=len, reverse=True))
        safe = re.sub(f"({pattern})", r"<mark>\1</mark>", safe, flags=re.I)
    st.markdown(safe.replace("\n", "<br>"), unsafe_allow_html=True)

    level = "High" if score >= 8 else "Medium" if score >= 4 else "Low"
    st.subheader(f"Risk level: {level}")
    st.progress(min(score / 12, 1.0))
    if level == "High":
        st.error("High risk: this looks like a scam.")
    elif level == "Medium":
        st.warning("Medium risk: be careful and verify first.")
    else:
        st.success("Low risk: no common scam signs found.")
    st.caption("A possible-risk estimate from simple rules, not a guarantee. "
               "Links are never opened by this tool.")

    if findings:
        st.subheader("Why it is risky")
        for title, why in findings:
            st.info(f"{title}\n\n💡 {why}")

    st.subheader("Safe next steps")
    st.write("- Don't click any link\n- Never share OTP, PIN or password\n"
             "- Verify using the official app or number\n"
             "- Report it (cybercrime.gov.in or call 1930) and delete the message")