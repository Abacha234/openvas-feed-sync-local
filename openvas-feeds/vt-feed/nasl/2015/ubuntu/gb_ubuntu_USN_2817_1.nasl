# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842540");
  script_cve_id("CVE-2015-5234", "CVE-2015-5235");
  script_tag(name:"creation_date", value:"2015-11-25 11:48:48 +0000 (Wed, 25 Nov 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2817-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2817-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2817-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web' package(s) announced via the USN-2817-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that IcedTea Web incorrectly handled applet URLs. A
remote attacker could possibly use this issue to inject applets into the
.appletTrustSettings configuration file and bypass user approval.
(CVE-2015-5234)

Andrea Palazzo discovered that IcedTea Web incorrectly determined the
origin of unsigned applets. A remote attacker could possibly use this issue
to bypass user approval, or to trick the user into approving applet
execution. (CVE-2015-5235)");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
