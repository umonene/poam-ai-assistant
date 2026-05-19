import json
import io
import os

import streamlit as st

APP_USERNAME = "demo"
APP_PASSWORD = "taemintech"

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("POA&M AI Assistant Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == APP_USERNAME and password == APP_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Invalid username or password")

    st.stop()
import pandas as pd
from dotenv import load_dotenv
from openai import OpenAI

# Load API key
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

st.title("POA&M AI Assistant (AI Version)")

uploaded_file = st.file_uploader(
    "Upload your findings file (CSV or Excel)",
    type=["csv", "xlsx"]
)


def generate_poam(finding):
    prompt = f"""
You are a cybersecurity compliance expert.

Return ONLY valid JSON. No explanation. No markdown. No extra text.

Format exactly like this:
{{
  "risk_statement": "...",
  "remediation_plan": "...",
  "milestone_1": "...",
  "milestone_2": "...",
  "milestone_3": "..."
}}

Finding: {finding}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    return response.choices[0].message.content.strip()


def generate_fix(finding):
    finding = str(finding).lower()

    if "openssl" in finding:
        return "Upgrade OpenSSL to the latest approved version. Restart affected services and validate remediation through vulnerability rescan."

    elif "password" in finding:
        return "Update password policy to enforce complexity, minimum length, password history, expiration, and account lockout settings."

    elif "ssh" in finding:
        return "Harden SSH configuration by disabling root login, disabling password authentication where possible, and restricting access to approved users."

    elif "firewall" in finding:
        return "Review firewall rules, remove unnecessary open ports, and restrict inbound and outbound access to approved sources only."

    elif "outdated" in finding or "patch" in finding:
        return "Apply vendor-approved patches or upgrade the affected software to a supported version, then validate remediation through rescan."

    else:
        return "Review the finding, identify the affected component, apply vendor-recommended remediation, and validate closure through security rescan."


def remediation_timeline(severity):
    severity = str(severity).lower()

    if severity == "critical":
        return "15 days"
    elif severity == "high":
        return "30 days"
    elif severity == "medium":
        return "60 days"
    elif severity == "low":
        return "90 days"
    else:
        return "Review required"


def get_finding_text(row, df):
    if "Finding Description" in df.columns:
        return row["Finding Description"]
    elif "Description" in df.columns:
        return row["Description"]
    elif "Plugin Name" in df.columns:
        return row["Plugin Name"]
    elif "Name" in df.columns:
        return row["Name"]
    elif "Synopsis" in df.columns:
        return row["Synopsis"]
    else:
        return "Unknown Finding"


def get_fix_source_column(df):
    if "Finding Description" in df.columns:
        return "Finding Description"
    elif "Description" in df.columns:
        return "Description"
    elif "Plugin Name" in df.columns:
        return "Plugin Name"
    elif "Name" in df.columns:
        return "Name"
    elif "Synopsis" in df.columns:
        return "Synopsis"
    else:
        return None


def get_severity_column(df):
    if "Severity" in df.columns:
        return "Severity"
    elif "Risk" in df.columns:
        return "Risk"
    elif "Plugin Severity" in df.columns:
        return "Plugin Severity"
    elif "Severity Level" in df.columns:
        return "Severity Level"
    else:
        return None


if uploaded_file:

    if uploaded_file.name.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
    else:
        df = pd.read_excel(uploaded_file)

    st.write("### Uploaded Data")
    st.write("Detected Columns:")
    st.write(df.columns.tolist())
    st.dataframe(df, use_container_width=True)

    if st.button("Generate POA&M"):

        risk_list = []
        rem_list = []
        m1_list = []
        m2_list = []
        m3_list = []

        for _, row in df.iterrows():
            finding_text = get_finding_text(row, df)

            try:
                ai_output = generate_poam(finding_text)
                ai_output = ai_output.replace("```json", "").replace("```", "").strip()

                data = json.loads(ai_output)

                risk_list.append(data.get("risk_statement", ""))
                rem_list.append(data.get("remediation_plan", ""))
                m1_list.append(data.get("milestone_1", ""))
                m2_list.append(data.get("milestone_2", ""))
                m3_list.append(data.get("milestone_3", ""))

            except Exception as e:
                risk_list.append("Error")
                rem_list.append(str(e))
                m1_list.append("")
                m2_list.append("")
                m3_list.append("")

        df["Risk Statement"] = risk_list
        df["Remediation Plan"] = rem_list
        df["Milestone 1"] = m1_list
        df["Milestone 2"] = m2_list
        df["Milestone 3"] = m3_list

        fix_source_column = get_fix_source_column(df)

        if fix_source_column:
            df["Recommended Fix"] = df[fix_source_column].apply(generate_fix)
        else:
            df["Recommended Fix"] = "Review the finding and apply vendor-recommended remediation."

        severity_column = get_severity_column(df)

        if severity_column:
            df["Remediation Timeline"] = df[severity_column].apply(remediation_timeline)
        else:
            df["Remediation Timeline"] = "Review Required"

        df["Status"] = "Open"

        st.write("### Generated POA&M (Structured)")
        st.write("Columns generated:")
        st.write(list(df.columns))
        st.dataframe(df, use_container_width=True)

        output = io.BytesIO()
        df.to_excel(output, index=False)
        output.seek(0)

        st.download_button(
            label="Download POA&M Excel",
            data=output,
            file_name="poam_output.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
