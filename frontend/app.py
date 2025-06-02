import streamlit as st
import requests
import json
import pandas as pd

API_URL = "http://localhost:8000" 

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user' not in st.session_state: 
    st.session_state.user = None
if 'action' not in st.session_state:
    st.session_state.action = None 
if 'editing_user_id' not in st.session_state: 
    st.session_state.editing_user_id = None
if 'editing_patient_user_id' not in st.session_state: 
    st.session_state.editing_patient_user_id = None
if 'selected_patient_for_doctor_user_id' not in st.session_state:
    st.session_state.selected_patient_for_doctor_user_id = None


def api_request(method, endpoint, json_payload=None, params=None, headers=None):
    url = f"{API_URL}{endpoint}"
    try:
        if st.session_state.logged_in and st.session_state.user:
            if headers is None: headers = {}
            headers["X-Username"] = st.session_state.user['username']

        response = requests.request(method, url, json=json_payload, params=params, headers=headers)
        response.raise_for_status() 
        if response.content:
            return response.json()
        return None
    except requests.exceptions.HTTPError as http_err:
        st.error(f"API Error: {http_err.response.status_code} - {http_err.response.text}")
    except requests.exceptions.RequestException as req_err:
        st.error(f"Connection Error: {req_err}")
    except json.JSONDecodeError:
        st.error("Error decoding JSON response from server.")
    return None


def login_page():
    st.title("🔐 Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if not username or not password:
                st.error("Please enter both username and password.")
                return
            response_data = api_request("POST", "/login", json_payload={"username": username, "password": password})
            if response_data:
                st.session_state.logged_in = True
                st.session_state.user = response_data 
                st.success("Login successful!")
                st.rerun() 

def registration_page():
    st.title("📝 Registration")
    reg_type = st.radio("Select Registration Type:", ["Admin Registers Staff/Doctor", "Self-Register (Analyst/Researcher)"])

    if reg_type == "Admin Registers Staff/Doctor":
        st.subheader("Admin Registration of Staff/Doctor")
        st.info("This action requires Admin credentials.")
        with st.form("admin_register_user_form"):
            st.write("**New User Credentials:**")
            new_username = st.text_input("New User's Username", key="reg_new_uname")
            new_password = st.text_input("New User's Password", type="password", key="reg_new_pass")
            confirm_password = st.text_input("Confirm New User's Password", type="password", key="reg_new_conf_pass")
            new_role = st.selectbox("Role for New User", ["staff", "doctor"], key="reg_new_role")
            
            st.write("**New User Details:**")
            new_name = st.text_input(f"{new_role.capitalize()}'s Name", key="reg_new_name")
            new_department = st.text_input("Department", key="reg_new_dept")
            new_shift_time = st.text_input("Shift Time", key="reg_new_shift")

            st.divider()
            st.write("**Admin Credentials for Authorization:**")
            admin_username = st.text_input("Your Admin Username", key="reg_admin_uname")
            admin_password = st.text_input("Your Admin Password", type="password", key="reg_admin_pass")
            
            submitted = st.form_submit_button("Register User")

            if submitted:
                if not all([new_username, new_password, confirm_password, new_role, new_name, admin_username, admin_password]):
                    st.error("Please fill all required fields.")
                elif new_password != confirm_password:
                    st.error("New user's passwords do not match.")
                else:
                    payload = {
                        "username": new_username, "password": new_password, "role": new_role,
                        "name": new_name, "department": new_department, "shift_time": new_shift_time,
                        "admin_username": admin_username, "admin_password": admin_password
                    }
                    response_data = api_request("POST", "/register_user_by_admin", json_payload=payload)
                    if response_data:
                        st.success(f"{new_role.capitalize()} '{new_username}' registered successfully!")
    
    elif reg_type == "Self-Register (Analyst/Researcher)":
        st.subheader("Self Registration (Analyst/Researcher)")
        with st.form("self_register_form"):
            username = st.text_input("Username", key="self_reg_uname")
            password = st.text_input("Password", type="password", key="self_reg_pass")
            confirm_password = st.text_input("Confirm Password", type="password", key="self_reg_conf_pass")
            role = st.selectbox("Your Role", ["analyst", "researcher"], key="self_reg_role")
            name = st.text_input("Your Name (Optional, defaults to username)", key="self_reg_name")
            submitted = st.form_submit_button("Register")

            if submitted:
                if not all([username, password, confirm_password, role]):
                    st.error("Please fill username, password, and role.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    payload = {"username": username, "password": password, "role": role, "name": name}
                    response_data = api_request("POST", "/register_self", json_payload=payload)
                    if response_data:
                        st.success("Registration successful! You can now login.")


def main_app_page():
    user = st.session_state.user
    st.sidebar.header(f"Welcome, {user['username']}")
    st.sidebar.caption(f"Role: {user['role'].capitalize()}")
    if st.sidebar.button("Logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.action = None 
        st.session_state.editing_user_id = None
        st.session_state.editing_patient_user_id = None
        st.session_state.selected_patient_for_doctor_user_id = None
        st.rerun()

    st.title("🏥 Healthcare Data System Dashboard")

    if user['role'] == 'admin':
        admin_actions()
    elif user['role'] == 'staff':
        staff_actions()
    elif user['role'] == 'doctor':
        doctor_actions()
    elif user['role'] in ['analyst', 'researcher']:
        analyst_researcher_actions()
    
    if st.session_state.action == "edit_staff_doctor_form" and st.session_state.editing_user_id:
        render_edit_staff_doctor_form(st.session_state.editing_user_id)
    elif st.session_state.action == "register_patient_form":
        render_register_patient_form()
    elif st.session_state.action == "edit_patient_form" and st.session_state.editing_patient_user_id:
        render_edit_patient_form(st.session_state.editing_patient_user_id)
    elif st.session_state.action == "view_patient_details_for_doctor" and st.session_state.selected_patient_for_doctor_user_id:
        render_patient_details_for_doctor(st.session_state.selected_patient_for_doctor_user_id)
    elif st.session_state.action == "submit_diagnosis_form" and st.session_state.selected_patient_for_doctor_user_id:
        render_submit_diagnosis_form(st.session_state.selected_patient_for_doctor_user_id)


def admin_actions():
    st.sidebar.subheader("Admin Menu")
    if st.sidebar.button("Manage Staff/Doctors", use_container_width=True):
        st.session_state.action = "manage_staff_doctor"
        st.rerun() 

    if st.session_state.action == "manage_staff_doctor":
        st.subheader("Manage Staff and Doctors")
        users_data = api_request("GET", "/users") 
        if users_data:
            staff_doctors = [u for u in users_data if u['role'] in ['staff', 'doctor']]
            if not staff_doctors:
                st.info("No staff or doctors found.")
                return

            df = pd.DataFrame(staff_doctors)[['id', 'username', 'role']]
            st.dataframe(df, use_container_width=True)

            selected_user_id = st.selectbox("Select User to Edit by ID", [sd['id'] for sd in staff_doctors], format_func=lambda x: f"{[sd for sd in staff_doctors if sd['id'] == x][0]['username']} (ID: {x})", index=None, placeholder="Choose a user...")
            if selected_user_id:
                st.session_state.editing_user_id = selected_user_id
                st.session_state.action = "edit_staff_doctor_form"
                st.rerun()
        else:
            st.warning("Could not fetch user list.")


def render_edit_staff_doctor_form(user_id_to_edit):
    st.subheader(f"Edit User (ID: {user_id_to_edit})")
  

    with st.form(f"edit_user_{user_id_to_edit}_form"):
        st.write("Enter new details (leave blank to keep current):")
        name = st.text_input("Name", key=f"edit_name_{user_id_to_edit}")
        department = st.text_input("Department", key=f"edit_dept_{user_id_to_edit}")
        shift_time = st.text_input("Shift Time", key=f"edit_shift_{user_id_to_edit}")
        
        st.divider()
        st.write("**Admin Credentials for Authorization:**")
        admin_username = st.text_input("Your Admin Username", key=f"edit_admin_uname_{user_id_to_edit}")
        admin_password = st.text_input("Your Admin Password", type="password", key=f"edit_admin_pass_{user_id_to_edit}")

        submitted = st.form_submit_button("Update User Details")
        if submitted:
            if not admin_username or not admin_password:
                st.error("Admin credentials are required.")
                return

            payload = {
                "name": name if name else None,
                "department": department if department else None,
                "shift_time": shift_time if shift_time else None,
                "admin_username": admin_username,
                "admin_password": admin_password
            }
            payload = {k: v for k, v in payload.items() if v is not None or k in ["admin_username", "admin_password"]}


            response = api_request("PUT", f"/admin/edit_user_details/{user_id_to_edit}", json_payload=payload)
            if response:
                st.success("User details updated successfully!")
                st.session_state.action = "manage_staff_doctor" #
                st.session_state.editing_user_id = None
                st.rerun()
    if st.button("Cancel Edit"):
        st.session_state.action = "manage_staff_doctor"
        st.session_state.editing_user_id = None
        st.rerun()


def staff_actions():
    st.sidebar.subheader("Staff Menu")
    if st.sidebar.button("Register New Patient", use_container_width=True):
        st.session_state.action = "register_patient_form"
        st.rerun()
    if st.sidebar.button("Manage Patients", use_container_width=True):
        st.session_state.action = "manage_patients_staff"
        st.rerun()

    if st.session_state.action == "manage_patients_staff":
        st.subheader("Manage Patients")
        users_data = api_request("GET", "/users")
        if users_data:
            patients = [u for u in users_data if u['role'] == 'patient']
            if not patients:
                st.info("No patients registered yet.")
                return

            patient_options = {}
            for p in patients:
                patient_profile = api_request("GET", f"/view_patient_data/{p['id']}")
                display_name = patient_profile.get("name", p['username']) if patient_profile else p['username']
                patient_options[p['id']] = display_name

            selected_patient_user_id = st.selectbox(
                "Select Patient to View/Edit by User ID", 
                options=list(patient_options.keys()), 
                format_func=lambda x: f"{patient_options[x]} (User ID: {x})",
                index=None,
                placeholder="Choose a patient..."
            )

            if selected_patient_user_id:
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Edit Patient Details", use_container_width=True):
                        st.session_state.editing_patient_user_id = selected_patient_user_id
                        st.session_state.action = "edit_patient_form"
                        st.rerun()
                with col2:
                    if st.button("View Patient Full Data", use_container_width=True):
                        patient_full_data = api_request("GET", f"/view_patient_data/{selected_patient_user_id}")
                        if patient_full_data:
                            st.json(patient_full_data) 
                        else:
                            st.error("Could not load patient data.")
        else:
            st.warning("Could not fetch patient list.")


def render_register_patient_form():
    st.subheader("Register New Patient")
    with st.form("register_patient_form_staff"):
        st.write("**Patient Information:**")
        name = st.text_input("Patient Full Name*", key="reg_p_name")
        mrn = st.text_input("Medical Record Number (MRN)*", key="reg_p_mrn")
        dob = st.date_input("Date of Birth", value=None, key="reg_p_dob")
        address = st.text_area("Address", key="reg_p_address")
        phone = st.text_input("Phone Number", key="reg_p_phone")
        email = st.text_input("Email Address", key="reg_p_email")
        genetic_data = st.text_area("Genetic Data (Optional)", key="reg_p_genetic")
        
        st.divider()
        st.write("**Data Consent:**")
        basic_consent = st.checkbox("Basic Consent: Encrypt all data fully.", key="reg_p_basic_consent")
        contact_sharing_consent = st.checkbox("Contact Info Sharing Consent: Allow partial visibility for phone/email.", key="reg_p_contact_consent")
        if not basic_consent and not contact_sharing_consent:
            st.warning("At least one consent option is recommended for data protection.")
        if basic_consent and contact_sharing_consent:
            st.info("Full encryption (Basic Consent) will take precedence if both are selected.")

        submitted = st.form_submit_button("Register Patient")

        if submitted:
            if not name or not mrn:
                st.error("Patient Name and MRN are required.")
                return

            payload = {
                "name": name, "mrn": mrn,
                "dob": str(dob) if dob else None,
                "address": address, "phone": phone, "email": email,
                "genetic_data": genetic_data,
                "basic_consent": basic_consent,
                "contact_sharing_consent": contact_sharing_consent,
                "staff_username": st.session_state.user['username'] 
            }
            response = api_request("POST", "/staff/register_patient", json_payload=payload)
            if response:
                st.success(f"Patient '{name}' (User: {response.get('username')}) registered successfully!")
                st.session_state.action = "manage_patients_staff" 
                st.rerun()
    if st.button("Cancel Registration"):
        st.session_state.action = "manage_patients_staff"
        st.rerun()


def render_edit_patient_form(patient_user_id):
    st.subheader(f"Edit Patient (User ID: {patient_user_id})")
    

    patient_data = api_request("GET", f"/view_patient_data/{patient_user_id}")
    if not patient_data:
        st.error("Could not load patient data to edit.")
        if st.button("Back to Patient List"):
            st.session_state.action = "manage_patients_staff"
            st.session_state.editing_patient_user_id = None
            st.rerun()
        return

    with st.form(f"edit_patient_{patient_user_id}_form"):
        st.write("**Patient Information (Edit as needed):**")
        name = st.text_input("Patient Full Name*", value=patient_data.get("name", ""), key=f"edit_p_name_{patient_user_id}")
        mrn = st.text_input("Medical Record Number (MRN)*", value=patient_data.get("mrn", ""), key=f"edit_p_mrn_{patient_user_id}", help="MRN typically should not be changed after creation or requires special handling.")
        
        dob_val = pd.to_datetime(patient_data.get("dob")).date() if patient_data.get("dob") else None
        dob = st.date_input("Date of Birth", value=dob_val, key=f"edit_p_dob_{patient_user_id}")
        
        address = st.text_area("Address", value=patient_data.get("address", ""), key=f"edit_p_address_{patient_user_id}")
        phone = st.text_input("Phone Number", value=patient_data.get("phone", ""), key=f"edit_p_phone_{patient_user_id}")
        email = st.text_input("Email Address", value=patient_data.get("email", ""), key=f"edit_p_email_{patient_user_id}")
        genetic_data = st.text_area("Genetic Data", value=patient_data.get("genetic_data", ""), key=f"edit_p_genetic_{patient_user_id}")
        
        st.text_input("Diagnosis (Current)", value=patient_data.get("diagnosis", ""), disabled=True)
        st.text_area("Prescription History (Current)", value=patient_data.get("prescription_history", ""), disabled=True)

        st.divider()
        st.write("**Data Consent (Current values shown, can be updated):**")
        basic_consent = st.checkbox("Basic Consent: Encrypt all data fully.", value=patient_data.get("basic_consent", False), key=f"edit_p_basic_consent_{patient_user_id}")
        contact_sharing_consent = st.checkbox("Contact Info Sharing Consent: Allow partial visibility for phone/email.", value=patient_data.get("contact_sharing_consent", False), key=f"edit_p_contact_consent_{patient_user_id}")
        if not basic_consent and not contact_sharing_consent:
            st.warning("At least one consent option is recommended for data protection.")

        submitted = st.form_submit_button("Update Patient Details")

        if submitted:
            if not name or not mrn:
                st.error("Patient Name and MRN are required.")
                return

            payload = {
                "name": name, "mrn": mrn,
                "dob": str(dob) if dob else None,
                "address": address, "phone": phone, "email": email,
                "genetic_data": genetic_data,
                "basic_consent": basic_consent,
                "contact_sharing_consent": contact_sharing_consent,
                "staff_username": st.session_state.user['username'] 
            }
            response = api_request("PUT", f"/staff/edit_patient/{patient_user_id}", json_payload=payload)
            if response:
                st.success(f"Patient details updated successfully!")
                st.session_state.action = "manage_patients_staff"
                st.session_state.editing_patient_user_id = None
                st.rerun()
    if st.button("Cancel Edit"):
        st.session_state.action = "manage_patients_staff"
        st.session_state.editing_patient_user_id = None
        st.rerun()


def doctor_actions():
    st.sidebar.subheader("Doctor Menu")
    if st.sidebar.button("Select Patient / View Data", use_container_width=True):
        st.session_state.action = "doctor_select_patient"
        st.session_state.selected_patient_for_doctor_user_id = None 
        st.rerun()

    if st.session_state.action == "doctor_select_patient":
        st.subheader("Patient Dashboard")
        patient_list_data = api_request("GET", "/patients_list_for_doctor")
        
        if patient_list_data:
            if not patient_list_data:
                st.info("No patients found in the system.")
                return

            patient_options = {
                p['user_id']: f"{p['display_name']} (MRN: {p['mrn']})" 
                for p in patient_list_data
            }
            
            patient_user_ids = list(patient_options.keys())

            if not patient_user_ids:
                st.info("No patients available for selection.")
                return

            selected_user_id = st.selectbox(
                "Select Patient:", 
                options=patient_user_ids, 
                format_func=lambda user_id: patient_options.get(user_id, f"Unknown User ID: {user_id}"), 
                index=None, 
                placeholder="Choose a patient..."
            )

            if selected_user_id:
                st.session_state.selected_patient_for_doctor_user_id = selected_user_id
                

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("View Patient Medical Record", use_container_width=True):
                        st.session_state.action = "view_patient_details_for_doctor"
                        st.rerun()
                with col2:
                    if st.button("Add/Update Diagnosis/Prescription", use_container_width=True):
                        st.session_state.action = "submit_diagnosis_form"
                        st.rerun()
        else:
            st.error("Could not fetch patient list.")
            st.info("Ensure the backend API for '/patients_list_for_doctor' is working correctly and returning data.")



def render_patient_details_for_doctor(patient_user_id):
    st.subheader(f"Medical Record for Patient (User ID: {patient_user_id})")
    patient_data = api_request("GET", f"/view_patient_data/{patient_user_id}")
    if patient_data:
        st.markdown(f"**Name:** {patient_data.get('name', 'N/A')}")
        st.markdown(f"**MRN:** {patient_data.get('mrn', 'N/A')}")
        st.markdown(f"**DOB:** {patient_data.get('dob', 'N/A')}")
        st.markdown(f"**Contact:** Phone: {patient_data.get('phone', 'N/A')}, Email: {patient_data.get('email', 'N/A')}")
        st.markdown(f"**Address:** {patient_data.get('address', 'N/A')}")
        
        st.divider()
        st.markdown("#### Medical Information")
        st.markdown(f"**Diagnosis:**")
        st.text_area("Current Diagnosis", value=patient_data.get('diagnosis', 'No diagnosis recorded.'), height=100, disabled=True, key="doc_view_diag")
        
        st.markdown(f"**Prescription History:**")
        st.text_area("Current Prescriptions", value=patient_data.get('prescription_history', 'No prescriptions recorded.'), height=150, disabled=True, key="doc_view_presc")
        
        st.markdown(f"**Genetic Data:**")
        st.text_area("Genetic Information", value=patient_data.get('genetic_data', 'N/A'), disabled=True, key="doc_view_genetic")

        st.divider()
        st.caption(f"Basic Consent Given: {patient_data.get('basic_consent')}, Contact Sharing Consent: {patient_data.get('contact_sharing_consent')}")

    else:
        st.error("Could not load patient data.")
    
    if st.button("Back to Patient Selection"):
        st.session_state.action = "doctor_select_patient"
        st.session_state.selected_patient_for_doctor_user_id = None
        st.rerun()


def render_submit_diagnosis_form(patient_user_id):
    st.subheader(f"Add/Update Medical Data for Patient (User ID: {patient_user_id})")
    
    patient_current_data = api_request("GET", f"/view_patient_data/{patient_user_id}")
    if not patient_current_data:
        st.error("Could not load current patient data.")
        if st.button("Back to Patient Selection"):
            st.session_state.action = "doctor_select_patient"
            st.session_state.selected_patient_for_doctor_user_id = None
            st.rerun()
        return

    st.info(f"Patient: {patient_current_data.get('name', 'N/A')} (MRN: {patient_current_data.get('mrn', 'N/A')})")

    with st.form(f"submit_diagnosis_form_{patient_user_id}"):
        diagnosis = st.text_area("Diagnosis:", value=patient_current_data.get('diagnosis', ''), height=150)
        prescription_history = st.text_area("Prescription History:", value=patient_current_data.get('prescription_history', ''), height=200)
        
        st.divider()
        st.write("**Patient Consent (Confirm or use existing):**")
        st.caption(f"Using patient's stored consent: Basic Consent: {patient_current_data.get('basic_consent')}, Contact Sharing: {patient_current_data.get('contact_sharing_consent')}")
        
        basic_consent_val = patient_current_data.get('basic_consent', False)
        contact_sharing_consent_val = patient_current_data.get('contact_sharing_consent', False)


        submitted = st.form_submit_button("Submit Medical Data")
        if submitted:
            if not diagnosis and not prescription_history:
                st.error("Please enter either diagnosis or prescription information.")
                return
            
            payload = {
                "patient_user_id": patient_user_id,
                "diagnosis": diagnosis,
                "prescription_history": prescription_history,
                "basic_consent": basic_consent_val, 
                "contact_sharing_consent": contact_sharing_consent_val, 
                "doctor_username": st.session_state.user['username']
            }
            response = api_request("POST", "/doctor/submit_patient_medical_data", json_payload=payload)
            if response:
                st.success("Medical data submitted successfully.")
                st.session_state.action = "view_patient_details_for_doctor" 
                st.rerun()
    
    if st.button("Cancel and Back to Patient Selection"):
        st.session_state.action = "doctor_select_patient"
        st.session_state.selected_patient_for_doctor_user_id = None
        st.rerun()

def analyst_researcher_actions():
    user_role = st.session_state.user['role']
    st.sidebar.subheader(f"{user_role.capitalize()} Menu")

    if st.sidebar.button(f"Submit New {user_role.capitalize()} Data", use_container_width=True):
        st.session_state.action = f"submit_{user_role}_data"
        st.rerun()
    if st.sidebar.button(f"View My {user_role.capitalize()} Submissions", use_container_width=True):
        st.session_state.action = f"view_my_{user_role}_submissions" 
        st.rerun()

    if st.session_state.action == f"submit_analyst_data" and user_role == "analyst":
        render_analyst_submit_form()
    elif st.session_state.action == f"submit_researcher_data" and user_role == "researcher":
        render_researcher_submit_form()
    elif st.session_state.action == f"view_my_{user_role}_submissions": 
        render_view_own_submissions()

def render_analyst_submit_form():
    st.subheader("Submit New Analyst Report/Data")
    with st.form("analyst_submit_form"):
        report_name = st.text_input("Report Name*", key="analyst_report_name")
        analysis_period = st.text_input("Analysis Period (e.g., Q1 2023, 2022 Annual)", key="analyst_period")
        disease_prevalence_data = st.text_area("Disease Prevalence Data (e.g., JSON format: {\"flu\": 0.1, \"covid\": 0.05})", key="analyst_disease_prev", height=100)
        resource_utilization_data = st.text_area("Healthcare Resource Utilization (e.g., JSON: {\"icu_beds_used\": 70, \"ventilators_avail\": 30})", key="analyst_resource_util", height=100)
        treatment_efficacy_stats = st.text_area("Treatment Efficacy Statistics (e.g., JSON or Text)", key="analyst_efficacy", height=100)
        public_health_trends = st.text_area("Observed Public Health Trends (Narrative)", key="analyst_trends", height=150)

        submitted = st.form_submit_button("Submit Analyst Data")
        if submitted:
            if not report_name:
                st.error("Report Name is required.")
                return
            
            payload = {
                "report_name": report_name,
                "analysis_period": analysis_period if analysis_period else None,
                "disease_prevalence_data": disease_prevalence_data if disease_prevalence_data else None,
                "resource_utilization_data": resource_utilization_data if resource_utilization_data else None,
                "treatment_efficacy_stats": treatment_efficacy_stats if treatment_efficacy_stats else None,
                "public_health_trends": public_health_trends if public_health_trends else None,
            }
            response = api_request("POST", "/analyst/submit_data", json_payload=payload)
            if response:
                st.success("Analyst data submitted successfully!")
                st.session_state.action = f"view_my_analyst_submissions" 
                st.rerun()
    if st.button("Cancel"):
        st.session_state.action = None
        st.rerun()


def render_researcher_submit_form():
    st.subheader("Submit New Researcher Study/Findings")
    with st.form("researcher_submit_form"):
        study_title = st.text_input("Study Title*", key="researcher_study_title")
        research_area = st.text_input("Research Area (e.g., Genomics, Oncology)", key="researcher_area")
        methodology_summary = st.text_area("Methodology Summary", key="researcher_methodology", height=100)
        key_findings = st.text_area("Key Findings (e.g., JSON or detailed text)", key="researcher_findings", height=150)
        anonymized_dataset_reference = st.text_input("Anonymized Dataset Reference/ID (if applicable)", key="researcher_dataset_ref")
        publication_link = st.text_input("Publication Link/DOI (if published)", key="researcher_pub_link")

        submitted = st.form_submit_button("Submit Research Data")
        if submitted:
            if not study_title:
                st.error("Study Title is required.")
                return
            
            payload = {
                "study_title": study_title,
                "research_area": research_area if research_area else None,
                "methodology_summary": methodology_summary if methodology_summary else None,
                "key_findings": key_findings if key_findings else None,
                "anonymized_dataset_reference": anonymized_dataset_reference if anonymized_dataset_reference else None,
                "publication_link": publication_link if publication_link else None,
            }
            response = api_request("POST", "/researcher/submit_data", json_payload=payload)
            if response:
                st.success("Researcher data submitted successfully!")
                st.session_state.action = f"view_my_researcher_submissions" 
                st.rerun()
    if st.button("Cancel"):
        st.session_state.action = None
        st.rerun()


def render_view_own_submissions():
    user_role = st.session_state.user['role']
    st.subheader(f"My {user_role.capitalize()} Submissions/Profile")
    
    profile_data = api_request("GET", f"/view_user_profile_data/{st.session_state.user['id']}")
    
    if profile_data:
        user_info = profile_data.get('user_info', {}) 
        st.markdown(f"**Username:** {user_info.get('username', 'N/A')}")
        st.markdown(f"**Role:** {user_info.get('role', 'N/A').capitalize()}")
        st.divider()

        if user_role == "analyst":
            st.markdown(f"### Analyst Data")
            st.markdown(f"**Analyst/Report Name (from profile.name):** {profile_data.get('name', 'N/A')}") 
            st.markdown(f"**Report Name (specific field):** {profile_data.get('report_name', 'N/A')}")
            st.markdown(f"**Analysis Period:** {profile_data.get('analysis_period', 'N/A')}")
            with st.expander("Disease Prevalence Data"):
                st.text(profile_data.get('disease_prevalence_data', 'N/A'))
        
        elif user_role == "researcher":
            st.markdown(f"### Researcher Data")
            st.markdown(f"**Researcher/Study Name (from profile.name):** {profile_data.get('name', 'N/A')}") 
            st.markdown(f"**Study Title (specific field):** {profile_data.get('study_title', 'N/A')}")
            st.markdown(f"**Research Area:** {profile_data.get('research_area', 'N/A')}")
        
        elif user_role in ["staff", "doctor"]: 
            st.markdown(f"### {user_role.capitalize()} Profile")
            st.markdown(f"**Name:** {profile_data.get('name', 'N/A')}")
            st.markdown(f"**Department:** {profile_data.get('department', 'N/A')}")
            st.markdown(f"**Shift Time:** {profile_data.get('shift_time', 'N/A')}")

        else:
            st.json(profile_data) 
            
    else:
        st.error(f"Could not load your {user_role} data. You may need to submit some data first or check API logs.")

    if st.button("Back to Dashboard"):
        st.session_state.action = None
        st.rerun()


def main():
    st.set_page_config(page_title="Healthcare Data System", layout="wide")

    if not st.session_state.logged_in:
        tabs = st.tabs(["Login", "Register"])
        with tabs[0]:
            login_page()
        with tabs[1]:
            registration_page()
    else:
        main_app_page()

if __name__ == "__main__":
    main()