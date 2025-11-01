# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703779");
  script_cve_id("CVE-2017-5488", "CVE-2017-5489", "CVE-2017-5490", "CVE-2017-5491", "CVE-2017-5492", "CVE-2017-5493", "CVE-2017-5610", "CVE-2017-5611", "CVE-2017-5612");
  script_tag(name:"creation_date", value:"2017-02-03 06:41:20 +0000 (Fri, 03 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-30 02:37:00 +0000 (Sat, 30 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-3779)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3779");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3779");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-3779 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in wordpress, a web blogging tool. They would allow remote attackers to hijack victims' credentials, access sensitive information, execute arbitrary commands, bypass read and post restrictions, or mount denial-of-service attacks.

For the stable distribution (jessie), these problems have been fixed in version 4.1+dfsg-1+deb8u12.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 4.7.1+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);