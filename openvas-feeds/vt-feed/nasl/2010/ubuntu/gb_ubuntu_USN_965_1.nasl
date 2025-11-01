# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840478");
  script_cve_id("CVE-2010-0211", "CVE-2010-0212");
  script_tag(name:"creation_date", value:"2010-08-13 12:24:53 +0000 (Fri, 13 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-965-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-965-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-965-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap, openldap2.2, openldap2.3' package(s) announced via the USN-965-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Using the Codenomicon LDAPv3 test suite, Ilkka Mattila and Tuomas
Salomaki discovered that the slap_modrdn2mods function in modrdn.c
in OpenLDAP does not check the return value from a call to the
smr_normalize function. A remote attacker could use specially crafted
modrdn requests to crash the slapd daemon or possibly execute arbitrary
code. (CVE-2010-0211)

Using the Codenomicon LDAPv3 test suite, Ilkka Mattila and Tuomas
Salomaki discovered that OpenLDAP does not properly handle empty
RDN strings. A remote attacker could use specially crafted modrdn
requests to crash the slapd daemon. (CVE-2010-0212)

In the default installation under Ubuntu 8.04 LTS and later, attackers
would be isolated by the OpenLDAP AppArmor profile for the slapd daemon.");

  script_tag(name:"affected", value:"'openldap, openldap2.2, openldap2.3' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
