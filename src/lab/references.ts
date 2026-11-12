// Public guidance cited by the Cyber Lab answer keys. Subcategory statements
// were checked against NIST CSWP 29 (CSF 2.0) when written; ATT&CK mitigation
// identifiers against the published ATT&CK dataset.

import type { Reference } from './model';

const CSF_URL = 'https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf';

/** NIST Cybersecurity Framework 2.0 subcategory, the structure used by NIST SP 800-61r3. */
export const csf = (id: string, statement: string): Reference => ({ label: `NIST CSF 2.0 ${id} — ${statement}`, url: CSF_URL });

export const SP800_61R3: Reference = { label: 'NIST SP 800-61r3 (April 2025)', url: 'https://csrc.nist.gov/pubs/sp/800/61/r3/final' };

export const mitigation = (id: string, name: string): Reference => ({ label: `MITRE ATT&CK ${id} ${name}`, url: `https://attack.mitre.org/mitigations/${id}/` });

export const CISA_RANSOMWARE: Reference = { label: 'CISA #StopRansomware Guide', url: 'https://www.cisa.gov/stopransomware/ransomware-guide' };

export const CISA_PLAYBOOKS: Reference = {
  label: 'CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks',
  url: 'https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks',
};

export const ANSSI_RANSOMWARE: Reference = { label: 'ANSSI — Attaques par rançongiciels, tous concernés', url: 'https://cyber.gouv.fr/publications/attaques-par-rancongiciels-tous-concernes' };

// Frequently cited CSF 2.0 subcategories (statements abridged).
export const DE_AE_02 = csf('DE.AE-02', 'Potentially adverse events are analyzed');
export const DE_AE_03 = csf('DE.AE-03', 'Information is correlated from multiple sources');
export const DE_AE_08 = csf('DE.AE-08', 'Incidents are declared when adverse events meet the defined incident criteria');
export const RS_AN_03 = csf('RS.AN-03', 'Analysis is performed to establish what has taken place during an incident');
export const RS_AN_07 = csf('RS.AN-07', 'Incident data and metadata are collected, and their integrity and provenance are preserved');
export const RS_AN_08 = csf('RS.AN-08', "An incident's magnitude is estimated and validated");
export const RS_MA_02 = csf('RS.MA-02', 'Incident reports are triaged and validated');
export const RS_MI_01 = csf('RS.MI-01', 'Incidents are contained');
export const RS_MI_02 = csf('RS.MI-02', 'Incidents are eradicated');
export const RS_CO_02 = csf('RS.CO-02', 'Internal and external stakeholders are notified of incidents');
export const RC_RP_03 = csf('RC.RP-03', 'The integrity of backups and other restoration assets is verified before using them for restoration');
export const RC_RP_05 = csf('RC.RP-05', 'The integrity of restored assets is verified, systems and services are restored');
export const PR_AA_03 = csf('PR.AA-03', 'Users, services, and hardware are authenticated');
export const PR_AA_05 = csf('PR.AA-05', 'Access permissions, entitlements, and authorizations are defined, managed, enforced, and reviewed');
export const PR_DS_11 = csf('PR.DS-11', 'Backups of data are created, protected, maintained, and tested');
export const PR_PS_01 = csf('PR.PS-01', 'Configuration management practices are established and applied');
export const PR_PS_02 = csf('PR.PS-02', 'Software is maintained, replaced, and removed commensurate with risk');
export const PR_PS_04 = csf('PR.PS-04', 'Log records are generated and made available for continuous monitoring');
export const PR_IR_01 = csf('PR.IR-01', 'Networks and environments are protected from unauthorized logical access and usage');
export const ID_IM_03 = csf('ID.IM-03', 'Improvements are identified from execution of operational processes');
