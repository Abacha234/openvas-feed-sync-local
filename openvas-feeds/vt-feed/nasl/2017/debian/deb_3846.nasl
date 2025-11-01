# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703846");
  script_cve_id("CVE-2017-6298", "CVE-2017-6299", "CVE-2017-6300", "CVE-2017-6301", "CVE-2017-6302", "CVE-2017-6303", "CVE-2017-6304", "CVE-2017-6305", "CVE-2017-6306", "CVE-2017-6800", "CVE-2017-6801", "CVE-2017-6802");
  script_tag(name:"creation_date", value:"2017-05-08 22:00:00 +0000 (Mon, 08 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-18 03:29:00 +0000 (Sat, 18 May 2019)");

  script_name("Debian: Security Advisory (DSA-3846)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3846");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3846");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libytnef' package(s) announced via the DSA-3846 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were discovered in libytnef, a library used to decode application/ms-tnef e-mail attachments. Multiple heap overflows, out-of-bound writes and reads, NULL pointer dereferences and infinite loops could be exploited by tricking a user into opening a maliciously crafted winmail.dat file.

For the stable distribution (jessie), these problems have been fixed in version 1.5-6+deb8u1.

For the upcoming stable (stretch) and unstable (sid) distributions, these problems have been fixed in version 1.9.2-1.

We recommend that you upgrade your libytnef packages.");

  script_tag(name:"affected", value:"'libytnef' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);