# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64573");
  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-810-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-810-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-810-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss' package(s) announced via the USN-810-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moxie Marlinspike discovered that NSS did not properly handle regular
expressions in certificate names. A remote attacker could create a
specially crafted certificate to cause a denial of service (via application
crash) or execute arbitrary code as the user invoking the program.
(CVE-2009-2404)

Moxie Marlinspike and Dan Kaminsky independently discovered that NSS did
not properly handle certificates with NULL characters in the certificate
name. An attacker could exploit this to perform a machine-in-the-middle attack
to view sensitive information or alter encrypted communications.
(CVE-2009-2408)

Dan Kaminsky discovered NSS would still accept certificates with MD2 hash
signatures. As a result, an attacker could potentially create a malicious
trusted certificate to impersonate another site. (CVE-2009-2409)");

  script_tag(name:"affected", value:"'nss' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
