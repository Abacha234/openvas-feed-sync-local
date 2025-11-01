# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845381");
  script_cve_id("CVE-2022-1520", "CVE-2022-1529", "CVE-2022-1802", "CVE-2022-29909", "CVE-2022-29911", "CVE-2022-29912", "CVE-2022-29913", "CVE-2022-29914", "CVE-2022-29916", "CVE-2022-29917");
  script_tag(name:"creation_date", value:"2022-05-24 01:01:13 +0000 (Tue, 24 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5435-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5435-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-5435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service,
bypass permission prompts, obtain sensitive information, bypass security
restrictions, cause user confusion, or execute arbitrary code.
(CVE-2022-29909, CVE-2022-29911, CVE-2022-29912, CVE-2022-29913,
CVE-2022-29914, CVE-2022-29916, CVE-2022-29917)

It was discovered that Thunderbird would show the wrong security status
after viewing an attached message that is signed or encrypted. An attacker
could potentially exploit this by tricking the user into trusting the
authenticity of a message. (CVE-2022-1520)

It was discovered that the methods of an Array object could be corrupted
as a result of prototype pollution by sending a message to the parent
process. If a user were tricked into opening a specially crafted website
in a browsing context, an attacker could exploit this to execute
JavaScript in a privileged context. (CVE-2022-1529, CVE-2022-1802)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
