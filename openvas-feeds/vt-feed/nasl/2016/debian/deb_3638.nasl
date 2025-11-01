# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703638");
  script_cve_id("CVE-2016-5419", "CVE-2016-5420", "CVE-2016-5421");
  script_tag(name:"creation_date", value:"2016-08-02 22:00:00 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-08 17:43:00 +0000 (Fri, 08 May 2020)");

  script_name("Debian: Security Advisory (DSA-3638)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3638");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3638");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-3638 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in cURL, an URL transfer library:

CVE-2016-5419

Bru Rom discovered that libcurl would attempt to resume a TLS session even if the client certificate had changed.

CVE-2016-5420

It was discovered that libcurl did not consider client certificates when reusing TLS connections.

CVE-2016-5421

Marcelo Echeverria and Fernando Munoz discovered that libcurl was vulnerable to a use-after-free flaw.

For the stable distribution (jessie), these problems have been fixed in version 7.38.0-4+deb8u4.

For the unstable distribution (sid), these problems have been fixed in version 7.50.1-1.

We recommend that you upgrade your curl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);