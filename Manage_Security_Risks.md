# MANAGE SECURITY RISKS

| **Domain** | **Description** | **Key Elements** |
| - | - | - |
| **1. Security and Risk Management**        | Establishing security posture, managing risk, ensuring compliance, and maintaining ethical/legal standards. | • Security goals & objectives<br>• Risk mitigation<br>• Compliance & legal regulations<br>• Business continuity<br>• InfoSec processes (incident response, vulnerability mgmt., app/cloud/infrastructure security)<br>**Example:** Updating PII handling to comply with GDPR. |
| **2. Asset Security**                      | Managing the lifecycle and protection of organizational assets and data.                                    | • Asset tracking<br>• Storage, maintenance, retention, destruction of data<br>• Backups & recovery planning<br>• Security impact analysis<br>**Example:** Backing up data to restore after incidents.                                                                         |
| **3. Security Architecture & Engineering** | Designing and implementing secure systems, tools, and processes.                                            | • Threat modeling<br>• Least privilege<br>• Defense in depth<br>• Fail securely<br>• Separation of duties<br>• Zero trust & “trust but verify”<br>**Example:** Using a SIEM to detect unusual login activity.                                                                 |
| **4. Communication & Network Security**    | Securing physical networks and wireless communication across on-site, remote, and cloud environments.       | • Network security controls<br>• Secure remote access<br>• Protecting data during travel/off-site work<br>**Example:** Restricting network access for remote workers.                                                                                                         |
| **5. Identity & Access Management (IAM)**  | Ensuring users are authenticated, authorized, and given minimal required access.                            | • User authentication<br>• Authorization controls<br>• Principle of least privilege<br>**Example:** Allowing customer service agents to view only necessary customer data, then revoking access.                                                                              |
| **6. Security Assessment & Testing**       | Identifying risks, threats, and vulnerabilities through assessments and audits.                             | • Penetration testing<br>• Security control testing<br>• Data collection & analysis<br>• Security audits<br>**Example:** Auditing user permissions to ensure appropriate access.                                                                                              |
| **7. Security Operations**                 | Managing, detecting, responding to, and preventing security incidents.                                      | • Intrusion detection/prevention<br>• SIEM & log management<br>• Incident management<br>• Playbooks<br>• Post-incident forensics<br>• Training & reporting<br>**Example:** Investigating late-night abnormal data access.                                                     |
| **8. Software Development Security**       | Building secure software by embedding security throughout the SDLC.                                         | • Secure coding practices<br>• Testing for vulnerabilities<br>• QA & pen testing<br>• Security reviews at each SDLC stage<br>**Example:** Ensuring encryption is configured on a medical device storing patient data.                                                         |

---

![cia](images/cia.png)

The **CIA triad** is a model that helps inform how organizations consider risk when setting up systems and security policies.

- **Confidentiality** is the idea that only authorized users can access specific assets or data. 
- **Integrity** is the idea that the data is verifiably correct, authentic, and reliable.
- **Availability** is the idea that data is accessible to those who are authorized to use it.

---

## **Risk Management Strategies**

Organizations protect assets by using strategies :

- **Acceptance:** Choose to live with a risk when avoiding it disrupts business.
- **Avoidance:** Eliminate the risk entirely.
- **Transference:** Shift the risk to a third party.
- **Mitigation:** Reduce the risk’s impact.

---

### **Threats**

A **threat** is anything that can harm assets :

- **Insider threats:** Authorized users misuse access.
- **Advanced persistent threats (APTs):** Long-term, stealthy unauthorized access.

---

### **Risks**

A **risk** is anything that could affect an asset’s confidentiality, integrity, or availability :

- **External risk:** Outside actors attempting to compromise assets.
- **Internal risk:** Employees, vendors, or partners posing security concerns.
- **Legacy systems:** Outdated systems that are still connected and vulnerable.
- **Multiparty risk:** Third-party vendors gaining access to sensitive information.
- **Software compliance/licensing:** Outdated or improperly licensed software and missing patches.

> Open Web Application Security Project ( OWASP ) publishes regularly updated lists of the top critical web application security risks.

---

### **Vulnerabilities**

A **vulnerability** is a weakness that threats can exploit :

- **ProxyLogon:** Microsoft Exchange flaw allowing remote code execution.
- **ZeroLogon:** Netlogon protocol flaw allowing unauthorized access.
- **Log4Shell:** Log4j flaw enabling remote code execution or data theft.
- **PetitPotam:** NTLM attack technique for forcing authentication requests.
- **Security logging/monitoring failures:** Poor detection capabilities.
- **Server-side request forgery (SSRF):** Attackers manipulate servers to access internal resources or steal data.

---
## SECURITY FRAMEWORKS

- Security frameworks provide structured guidelines for managing and reducing risks to data and privacy.
- Security controls are specific safeguards designed to address individual security risks.
- The **Cyber Threat Framework (CTF)** is a U.S. government–developed standard that provides a common language for describing cyber threat activity.
- The CTF enhances communication, analysis, and response capabilities among cybersecurity professionals.
- The **ISO/IEC 27001** framework is an internationally recognized standard for managing information security.
- ISO/IEC 27001 defines requirements and best practices for establishing an information security management system (ISMS).
- It includes a catalog of optional controls that organizations can adopt to strengthen their security posture.

**Security Controls** support frameworks by reducing the likelihood and impact of threats.

- **Physical controls:** gates, locks, guards, CCTV, access badges
- **Technical controls:** firewalls, MFA, antivirus software
- **Administrative controls:** separation of duties, authorization, asset classification

### NIST FRAMEWORK

---

**7 steps of the NIST Risk Management Framework (RMF)**

| **Step** | **Name** | **Description** |
| - | - | - |
| **1**    | **Prepare**    | Establish context, priorities, and readiness for managing security and privacy risk.|
| **2**    | **Categorize** | Categorize the information system and the data it processes based on impact levels.|
| **3**    | **Select**     | Choose appropriate security controls from NIST SP 800-53 based on the system’s categorization.|
| **4**    | **Implement**  | Deploy the selected security controls and document how they are implemented.|
| **5**    | **Assess**     | Evaluate whether the controls are correctly implemented and effective.|
| **6**    | **Authorize**  | Senior officials decide whether to authorize the system for operation based on risk.|
| **7**    | **Monitor**    | Continuously track security controls, risks, and changes to the system over time.|

---

**6 steps of the NIST Cybersecurity Framework (CSF)**

| **Step** | **Function** | **Description** |
| - | - | - |
| **1**    | **Govern**   | Establish risk management strategy, policies, and governance.|
| **2**    | **Identify** | Understand assets, systems, data, and associated risks.|
| **3**    | **Protect**  | Implement safeguards to prevent or limit cybersecurity impacts.|
| **4**    | **Detect**   | Identify cybersecurity events, anomalies, or issues.|
| **5**    | **Respond**  | Take action when a security event occurs.|
| **6**    | **Recover**  | Restore capabilities or services after a cybersecurity incident.|

---

### OWASP FRAMEWORK

The **OWASP Framework** outlines core security principles that guide organizations in building and maintaining secure systems. These principles include:

| **Principle** | **Description** |
| - | - |
| **Minimize attack surface area**  | Reduce the number of potential vulnerabilities an attacker can exploit.|
| **Least privilege**               | Give users only the access necessary to perform their tasks.|
| **Defense in depth**              | Implement multiple layers of security controls to mitigate risks.|
| **Separation of duties**          | Distribute critical responsibilities among multiple people, each with limited privileges.|
| **Keep security simple**          | Avoid unnecessary complexity, as it introduces additional risks.|
| **Fix security issues correctly** | Address root causes, contain impact, identify vulnerabilities, and test remediation.|
| **Secure defaults**               | Systems should start in their most secure configuration by default.|
| **Fail securely**                 | Controls should default to secure behavior when they fail.|
| **Don’t trust services**          | Validate security when working with third-party partners; don’t assume their systems are secure.|
| **Avoid security by obscurity**   | Security should rely on robust controls, not secrecy.|

---

## SECURITY AUDIT

- A **security audit** is an independent review of an organization’s security controls, policies, and procedures.
- Audits ensure compliance with internal standards and external regulatory requirements.
- They verify that security measures function properly and identify threats or vulnerabilities.
- Audits also ensure remediation processes exist to maintain a strong security posture.
- The **goal** of a security audit is to confirm that IT practices align with organizational and industry standards.
- The **objective** is to identify weaknesses, guide remediation, and prevent legal or regulatory penalties.
- Audit frequency depends on factors such as:

    + Laws and regulatory requirements
    + Compliance standards
    + Industry type
    + Organization size
    + Regulatory or contractual obligations
    + Geographic location
    + Voluntary compliance decisions

- Frameworks like **NIST CSF** and **ISO 27000** provide structured guidance to help organizations prepare for internal and external audits.
- Audit reviews typically cover three categories of controls:

    + **Administrative/managerial controls**
    + **Technical controls**
    + **Physical controls**

Before conducting an audit, organizations create an **audit checklist** that includes:

| **Step** | **Activity** | **Description** |
| - | - | - |
| **1**    | **Defining the audit scope**              | Identify assets to be assessed, goals, audit frequency, and policies to be evaluated.|
| **2**    | **Completing a risk assessment**          | Assess budget, controls, internal processes, and external regulatory requirements.|
| **3**    | **Conducting the audit**                  | Evaluate the security of all assets included in the audit scope.|
| **4**    | **Creating a mitigation plan**            | Develop actions to reduce risks, costs, or potential penalties.|
| **5**    | **Communicating results to stakeholders** | Report findings, recommended improvements, and compliance needs.|

---

## SIEM

A **SIEM** system gathers and analyzes logs from across an organization to deliver real-time monitoring, detect threats, and support incident investigations.

SIEM log sources include:

| **Log Category** | **Examples** |
| - | - |
| **Network & Infrastructure logs** | Firewall, routers/switches, VPN, DNS.|
| **System & Host logs**            | OS events, EDR data, authentication logs, Active Directory.|
| **Application & Service logs**    | Web servers, databases, cloud audit logs, email servers.|
| **Security tool logs**            | IDS/IPS, antivirus, DLP.|

A **SOAR** platform automates and streamlines incident response to improve speed and consistency.\
**Suricata** provides open-source network intrusion detection and analysis, while **Splunk** and **Chronicle** are SIEM tools that visualize log data to help teams monitor and detect threats.

---

### **Splunk Dashboards**

- **Security Posture Dashboard:** Monitors notable security events from the past 24 hours for real-time threat assessment.
- **Executive Summary Dashboard:** Provides high-level summaries of security trends for stakeholder reporting.
- **Incident Review Dashboard:** Highlights suspicious patterns and timelines for incidents requiring immediate attention.
- **Risk Analysis Dashboard:** Tracks abnormal activity to prioritize mitigation for high-risk users, devices, or IPs.

### **Chronicle Dashboards**

- **Enterprise Insights Dashboard:** Monitors alerts, suspicious domains, and severity for critical assets.
- **Data Ingestion and Health Dashboard:** Tracks log volumes and ingestion success to ensure proper log collection.
- **IOC Matches Dashboard:** Shows IOC activity trends to prioritize high-risk threats.
- **Main Dashboard:** Offers an overview of data ingestion, alerts, and event patterns across systems.
- **Rule Detections Dashboard:** Displays detection rule statistics to understand recurring or severe threats.
- **User Sign-In Overview Dashboard:** Monitors user login activity to detect anomalies like simultaneous logins from different locations.

---

## PLAYBOOK

A **playbook** is a living manual of predefined steps for responding to security incidents or operations, paired with a **strategy** outlining team expectations and a **plan** detailing task execution, and regularly updated to reflect evolving threats and standards.

Updates usually occur when:

- Failures or oversights are identified
- Industry standards, laws, or compliance requirements change
- Cyber threat tactics evolve

Organizations develop playbooks for specific incidents—like ransomware, vishing, etc.. tailored to regulatory and data-handling requirements.\
Common types include **incident response** and **vulnerability response** playbooks, which support business continuity, compliance, error reduction, forensic data integrity, and timely action.

Typical steps in these playbooks include:

| **Step** | **Phase**                    | **Description**                                                                            |
| -------- | ---------------------------- | ------------------------------------------------------------------------------------------ |
| **1**    | **Preparation**              | Set up tools, roles, procedures, and defenses so the team is ready for incidents.          |
| **2**    | **Detection**                | Identify suspicious activity through alerts, logs, and monitoring.                         |
| **3**    | **Analysis**                 | Investigate to determine the incident’s cause, scope, and impact.                          |
| **4**    | **Containment**              | Take immediate steps to limit damage and prevent further spread.                           |
| **5**    | **Eradication**              | Remove the threat completely by eliminating malicious files, accounts, or vulnerabilities. |
| **6**    | **Recovery**                 | Restore systems and operations to normal while monitoring for lingering issues.            |
| **7**    | **Post-Incident Activities** | Review what happened, update playbooks, and improve future response processes.             |
