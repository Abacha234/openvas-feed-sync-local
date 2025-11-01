# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856348");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:39 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for ca (SUSE-SU-2024:2869-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2869-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4G5DGDYGIMGM3KWF56HBRJZLMICTGALD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ca'
  package(s) announced via the SUSE-SU-2024:2869-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ca-certificates-mozilla fixes the following issues:

  * Updated to 2.68 state of Mozilla SSL root CAs (bsc#1227525)

  * Added: FIRMAPROFESIONAL CA ROOT-A WEB

  * Distrust: GLOBALTRUST 2020

  * Updated to 2.66 state of Mozilla SSL root CAs (bsc#1220356) Added:

  * CommScope Public Trust ECC Root-01

  * CommScope Public Trust ECC Root-02

  * CommScope Public Trust RSA Root-01

  * CommScope Public Trust RSA Root-02

  * D-Trust SBR Root CA 1 2022

  * D-Trust SBR Root CA 2 2022

  * Telekom Security SMIME ECC Root 2021

  * Telekom Security SMIME RSA Root 2023

  * Telekom Security TLS ECC Root 2020

  * Telekom Security TLS RSA Root 2023

  * TrustAsia Global Root CA G3

  * TrustAsia Global Root CA G4 Removed:

  * Autoridad de Certificacion Firmaprofesional CIF A62634068

  * Chambers of Commerce Root - 2008

  * Global Chambersign Root - 2008

  * Security Communication Root CA

  * Symantec Class 1 Public Primary Certification Authority - G6

  * Symantec Class 2 Public Primary Certification Authority - G6

  * TrustCor ECA-1

  * TrustCor RootCert CA-1

  * TrustCor RootCert CA-2

  * VeriSign Class 1 Public Primary Certification Authority - G3

  * VeriSign Class 2 Public Primary Certification Authority - G3

  ##");

  script_tag(name:"affected", value:"'ca' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
