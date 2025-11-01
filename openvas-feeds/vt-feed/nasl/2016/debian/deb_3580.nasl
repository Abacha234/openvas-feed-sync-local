# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703580");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718", "CVE-2016-5239");
  script_tag(name:"creation_date", value:"2016-05-15 22:00:00 +0000 (Sun, 15 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 13:29:00 +0000 (Mon, 15 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-3580)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3580");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3580");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-3580 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nikolay Ermishkin from the Mail.Ru Security Team and Stewie discovered several vulnerabilities in ImageMagick, a program suite for image manipulation. These vulnerabilities, collectively known as ImageTragick, are the consequence of lack of sanitization of untrusted input. An attacker with control on the image input could, with the privileges of the user running the application, execute code (CVE-2016-3714), make HTTP GET or FTP requests (CVE-2016-3718), or delete (CVE-2016-3715), move (CVE-2016-3716), or read (CVE-2016-3717) local files.

These vulnerabilities are particularly critical if Imagemagick processes images coming from remote parties, such as part of a web service.

The update disables the vulnerable coders (EPHEMERAL, URL, MVG, MSL, and PLT) and indirect reads via /etc/ImageMagick-6/policy.xml file. In addition, we introduce extra preventions, including some sanitization for input filenames in http/https delegates, the full remotion of PLT/Gnuplot decoder, and the need of explicit reference in the filename for the insecure coders.

For the stable distribution (jessie), these problems have been fixed in version 8:6.8.9.9-5+deb8u2.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);