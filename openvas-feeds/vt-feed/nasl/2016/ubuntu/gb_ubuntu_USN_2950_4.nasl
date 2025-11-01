# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842767");
  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"creation_date", value:"2016-05-19 03:20:59 +0000 (Thu, 19 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2950-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2950-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2950-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1576109");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1574403");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-2950-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2950-1 fixed vulnerabilities in Samba. The backported fixes introduced
in Ubuntu 12.04 LTS caused interoperability issues. This update fixes
compatibility with certain NAS devices, and allows connecting to Samba 3.6
servers by relaxing the 'client ipc signing' parameter to 'auto'.

We apologize for the inconvenience.

Original advisory details:

 Jouni Knuutinen discovered that Samba contained multiple flaws in the
 DCE/RPC implementation. A remote attacker could use this issue to perform
 a denial of service, downgrade secure connections by performing a
 machine-in-the-middle attack, or possibly execute arbitrary code.
 (CVE-2015-5370)

 Stefan Metzmacher discovered that Samba contained multiple flaws in the
 NTLMSSP authentication implementation. A remote attacker could use this
 issue to downgrade connections to plain text by performing a
 machine-in-the-middle attack. (CVE-2016-2110)

 Alberto Solino discovered that a Samba domain controller would establish a
 secure connection to a server with a spoofed computer name. A remote
 attacker could use this issue to obtain sensitive information.
 (CVE-2016-2111)

 Stefan Metzmacher discovered that the Samba LDAP implementation did not
 enforce integrity protection. A remote attacker could use this issue to
 hijack LDAP connections by performing a machine-in-the-middle attack.
 (CVE-2016-2112)

 Stefan Metzmacher discovered that Samba did not validate TLS certificates.
 A remote attacker could use this issue to spoof a Samba server.
 (CVE-2016-2113)

 Stefan Metzmacher discovered that Samba did not enforce SMB signing even if
 configured to. A remote attacker could use this issue to perform a
 machine-in-the-middle attack. (CVE-2016-2114)

 Stefan Metzmacher discovered that Samba did not enable integrity protection
 for IPC traffic. A remote attacker could use this issue to perform a
 machine-in-the-middle attack. (CVE-2016-2115)

 Stefan Metzmacher discovered that Samba incorrectly handled the MS-SAMR and
 MS-LSAD protocols. A remote attacker could use this flaw with a
 machine-in-the-middle attack to impersonate users and obtain sensitive
 information from the Security Account Manager database. This flaw is
 known as Badlock. (CVE-2016-2118)

 Samba has been updated to 4.3.8 in Ubuntu 14.04 LTS and Ubuntu 15.10.
 Ubuntu 12.04 LTS has been updated to 3.6.25 with backported security fixes.

 In addition to security fixes, the updated packages contain bug fixes,
 new features, and possibly incompatible changes. Configuration changes may
 be required in certain environments.");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
