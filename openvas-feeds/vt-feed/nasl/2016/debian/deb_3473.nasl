# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703473");
  script_cve_id("CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747");
  script_tag(name:"creation_date", value:"2016-02-10 23:00:00 +0000 (Wed, 10 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:13:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-3473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3473");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3473");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nginx' package(s) announced via the DSA-3473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the resolver in nginx, a small, powerful, scalable web/proxy server, leading to denial of service or, potentially, to arbitrary code execution. These only affect nginx if the resolver directive is used in a configuration file.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.2.1-2.2+wheezy4.

For the stable distribution (jessie), these problems have been fixed in version 1.6.2-5+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 1.9.10-1.

For the unstable distribution (sid), these problems have been fixed in version 1.9.10-1.

We recommend that you upgrade your nginx packages.");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);