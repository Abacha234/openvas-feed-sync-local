# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840794");
  script_cve_id("CVE-2011-3148", "CVE-2011-3149", "CVE-2011-3628");
  script_tag(name:"creation_date", value:"2011-10-31 12:45:00 +0000 (Mon, 31 Oct 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1237-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1237-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1237-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the USN-1237-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kees Cook discovered that the PAM pam_env module incorrectly handled
certain malformed environment files. A local attacker could use this flaw
to cause a denial of service, or possibly gain privileges. The default
compiler options for affected releases should reduce the vulnerability to a
denial of service. (CVE-2011-3148)

Kees Cook discovered that the PAM pam_env module incorrectly handled
variable expansion. A local attacker could use this flaw to cause a denial
of service. (CVE-2011-3149)

Stephane Chazelas discovered that the PAM pam_motd module incorrectly
cleaned the environment during execution of the motd scripts. In certain
environments, a local attacker could use this to execute arbitrary code
as root, and gain privileges.");

  script_tag(name:"affected", value:"'pam' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
