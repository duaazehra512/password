import streamlit as st
import re
import math
import random
import string
import requests

# --- Constants & Config ---
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123", "111111"
}

SPECIAL_CHARS = r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/\\|`~]"

RULES = [
    (lambda p: len(p) >= 8, "Use at least 8 characters."),
    (lambda p: re.search(r"[a-z]", p), "Include lowercase letters."),
    (lambda p: re.search(r"[A-Z]", p), "Include uppercase letters."),
    (lambda p: re.search(r"[0-9]", p), "Include numbers."),
    (lambda p: re.search(SPECIAL_CHARS, p), "Add special characters.")
]

# --- Memoizing Functions ---
@st.cache_data
def calculate_strength(password):
    score = 0
    feedback = []

    for check, message in RULES:
        if check(password):
            score += 1
        else:
            feedback.append(message)

    return score, feedback

@st.cache_data
def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(SPECIAL_CHARS, password): pool += 32
    return round(len(password) * math.log2(pool)) if pool else 0

# --- Get Strength Label ---
def get_strength_label(score):
    labels = [
        ("Very Weak", "red"),
        ("Weak", "orange"),
        ("Moderate", "gold"),
        ("Strong", "lightgreen"),
        ("Very Strong", "green")
    ]
    return labels[min(score, 4)]

# --- Password Generator ---
def generate_password(length=12, use_symbols=True):
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+=-"
    return ''.join(random.choice(chars) for i in range(length))

# --- Password Pwned Check ---
def check_pwned_password(password):
    url = f"https://api.pwnedpasswords.com/range/{password[:5]}"
    response = requests.get(url)
    return response.status_code == 200  # If password is found in pwned database

# --- Streamlit UI ---
st.set_page_config(page_title="Password Strength Meter", page_icon="🔐")
st.title("🔐 Password Strength Meter By Duaa Raza")

# Account type selection for tailored recommendations
account_type = st.selectbox("Select Account Type", ["Email", "Banking", "Work", "Social Media"])

# Display relevant recommendation based on account type
if account_type == "Banking":
    st.write("💡 Use at least 16 characters and include 2-factor authentication.")
elif account_type == "Email":
    st.write("💡 Use at least 12 characters with a mix of symbols, numbers, and letters.")
else:
    st.write("💡 Use at least 8 characters, with a combination of letters and numbers.")

show_password = st.checkbox("Show password")
password = st.text_input("Enter your password:", type="default" if show_password else "password")

if password:
    st.divider()

    # Check for common passwords
    if password.lower() in COMMON_PASSWORDS:
        st.error("🚨 This is a **very common** password. Avoid using it!")

    # Check if password is pwned
    if check_pwned_password(password):
        st.error("🚨 This password has been exposed in data breaches!")

    # Calculate strength and feedback
    score, feedback = calculate_strength(password)
    label, color = get_strength_label(score)
    entropy = calculate_entropy(password)

    st.markdown(f"### Strength: <span style='color:{color}'>{label}</span>", unsafe_allow_html=True)
    st.progress(score / 5)
    st.metric("🔢 Entropy", f"{entropy} bits")

    # Show gradient bar for strength
    st.markdown(f"""
    <div style="width:100%; height:30px; background: linear-gradient(to right, red, orange, gold, lightgreen, green);
    width:{score * 20}%"></div>
    """, unsafe_allow_html=True)

    # Copy to clipboard button
    st.markdown(
        f"""
        <button onclick="navigator.clipboard.writeText('{password}')"
        style="padding:6px 12px; background-color:#4CAF50; color:white; border:none; border-radius:4px; cursor:pointer;">
        📋 Copy Password
        </button>
        """,
        unsafe_allow_html=True
    )

    # Display feedback for improvement
    if feedback:
        st.markdown("### Suggestions to improve:")
        for tip in feedback:
            st.write(f"• {tip}")

    # Display password history
    if 'history' not in st.session_state:
        st.session_state.history = []

    # Log current password strength and entropy
    st.session_state.history.append({'password': password, 'strength': label, 'entropy': entropy})

    st.write("### Previous Password Strengths:")
    for entry in st.session_state.history:
        st.write(f"Password: {entry['password']}, Strength: {entry['strength']}, Entropy: {entry['entropy']} bits")

    # Password Generator
    st.header("Generate a Strong Password")
    length = st.slider("Password Length", 8, 20, 16)
    use_symbols = st.checkbox("Include Symbols", True)
    generated_password = generate_password(length, use_symbols)
    st.text_input("Generated Password", value=generated_password, key="generated", disabled=True)
    st.button("Copy Generated Password", on_click=lambda: st.text(generated_password))

