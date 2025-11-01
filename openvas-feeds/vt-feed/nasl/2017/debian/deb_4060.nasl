# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704060");
  script_cve_id("CVE-2017-11408", "CVE-2017-17083", "CVE-2017-17084", "CVE-2017-17085");
  script_tag(name:"creation_date", value:"2017-12-08 23:00:00 +0000 (Fri, 08 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)");

  script_name("Debian: Security Advisory (DSA-4060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4060");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4060");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wireshark");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-4060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that wireshark, a network protocol analyzer, contained several vulnerabilities in the dissectors for CIP Safety, IWARP_MPA, NetBIOS, Profinet I/O and AMQP, which result in denial of dervice or the execution of arbitrary code.

For the oldstable distribution (jessie), these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u12.

For the stable distribution (stretch), these problems have been fixed in version 2.2.6+g32dac6a-2+deb9u1.

We recommend that you upgrade your wireshark packages.

For the detailed security status of wireshark please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);