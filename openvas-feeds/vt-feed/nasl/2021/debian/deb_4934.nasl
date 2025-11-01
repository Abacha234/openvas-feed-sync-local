# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704934");
  script_cve_id("CVE-2020-24489", "CVE-2020-24511", "CVE-2020-24512", "CVE-2020-24513");
  script_tag(name:"creation_date", value:"2021-06-28 03:00:06 +0000 (Mon, 28 Jun 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 18:46:00 +0000 (Thu, 01 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-4934)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4934");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4934");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/issues/56");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/issues/31");
  script_xref(name:"URL", value:"https://salsa.debian.org/hmh/intel-microcode/-/blob/master/debian/README.Debian");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/intel-microcode");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'intel-microcode' package(s) announced via the DSA-4934 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update ships updated CPU microcode for some types of Intel CPUs and provides mitigations for security vulnerabilities which could result in privilege escalation in combination with VT-d and various side channel attacks.

For the stable distribution (buster), these problems have been fixed in version 3.20210608.2~deb10u1.

Note that there are two reported regressions, for some CoffeeLake CPUs this update may break iwlwifi ([link moved to references]) and some for Skylake R0/D0 CPUs on systems using a very outdated firmware/BIOS, the system may hang on boot: ([link moved to references])

If you are affected by those issues, you can recover by disabling microcode loading on boot (as documented in README.Debian, also available online at [link moved to references])

We recommend that you upgrade your intel-microcode packages.

For the detailed security status of intel-microcode please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);