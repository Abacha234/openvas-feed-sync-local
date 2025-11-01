# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704517");
  script_cve_id("CVE-2019-15846");
  script_tag(name:"creation_date", value:"2019-09-07 02:00:05 +0000 (Sat, 07 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4517)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4517");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4517");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/exim4");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exim4' package(s) announced via the DSA-4517 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'Zerons' and Qualys discovered that a buffer overflow triggerable in the TLS negotiation code of the Exim mail transport agent could result in the execution of arbitrary code with root privileges.

For the oldstable distribution (stretch), this problem has been fixed in version 4.89-2+deb9u6.

For the stable distribution (buster), this problem has been fixed in version 4.92-8+deb10u2.

We recommend that you upgrade your exim4 packages.

For the detailed security status of exim4 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'exim4' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);