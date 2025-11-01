# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704081");
  script_cve_id("CVE-2017-11142", "CVE-2017-11143", "CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11628", "CVE-2017-12933", "CVE-2017-16642", "CVE-2018-5711", "CVE-2018-5712");
  script_tag(name:"creation_date", value:"2018-01-07 23:00:00 +0000 (Sun, 07 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4081)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4081");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4081");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php5");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-4081 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in PHP, a widely-used open source general purpose scripting language:

CVE-2017-11142

Denial of service via overly long form variables

CVE-2017-11143

Invalid free() in wddx_deserialize()

CVE-2017-11144

Denial of service in openssl extension due to incorrect return value check of OpenSSL sealing function.

CVE-2017-11145

Out-of-bounds read in wddx_deserialize()

CVE-2017-11628

Buffer overflow in PHP INI parsing API

CVE-2017-12933

Buffer overread in finish_nested_data()

CVE-2017-16642

Out-of-bounds read in timelib_meridian()

For the oldstable distribution (jessie), these problems have been fixed in version 5.6.33+dfsg-0+deb8u1.

We recommend that you upgrade your php5 packages.

For the detailed security status of php5 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);