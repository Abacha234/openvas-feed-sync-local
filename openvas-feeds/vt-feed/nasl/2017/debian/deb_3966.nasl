# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703966");
  script_cve_id("CVE-2015-9096", "CVE-2016-7798", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-14064");
  script_tag(name:"creation_date", value:"2017-09-04 22:00:00 +0000 (Mon, 04 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-13 18:48:00 +0000 (Mon, 13 May 2019)");

  script_name("Debian: Security Advisory (DSA-3966)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3966");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3966");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.3' package(s) announced via the DSA-3966 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the interpreter for the Ruby language:

CVE-2015-9096

SMTP command injection in Net::SMTP.

CVE-2016-7798

Incorrect handling of initialization vector in the GCM mode in the OpenSSL extension.

CVE-2017-0900

Denial of service in the RubyGems client.

CVE-2017-0901

Potential file overwrite in the RubyGems client.

CVE-2017-0902

DNS hijacking in the RubyGems client.

CVE-2017-14064

Heap memory disclosure in the JSON library.

For the stable distribution (stretch), these problems have been fixed in version 2.3.3-1+deb9u1. This update also hardens RubyGems against malicious terminal escape sequences (CVE-2017-0899).

We recommend that you upgrade your ruby2.3 packages.");

  script_tag(name:"affected", value:"'ruby2.3' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);