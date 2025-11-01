# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704165");
  script_cve_id("CVE-2018-8763");
  script_tag(name:"creation_date", value:"2018-04-02 22:00:00 +0000 (Mon, 02 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-19 19:19:00 +0000 (Thu, 19 Apr 2018)");

  script_name("Debian: Security Advisory (DSA-4165)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4165");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4165");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ldap-account-manager");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ldap-account-manager' package(s) announced via the DSA-4165 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michal Kedzior found two vulnerabilities in LDAP Account Manager, a web front-end for LDAP directories.

CVE-2018-8763

The found Reflected Cross Site Scripting (XSS) vulnerability might allow an attacker to execute JavaScript code in the browser of the victim or to redirect her to a malicious website if the victim clicks on a specially crafted link.

CVE-2018-8764

The application leaks the CSRF token in the URL, which can be use by an attacker to perform a Cross-Site Request Forgery attack, in which a victim logged in LDAP Account Manager might performed unwanted actions in the front-end by clicking on a link crafted by the attacker.

For the oldstable distribution (jessie), these problems have been fixed in version 4.7.1-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 5.5-1+deb9u1.

We recommend that you upgrade your ldap-account-manager packages.

For the detailed security status of ldap-account-manager please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ldap-account-manager' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);