# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842682");
  script_cve_id("CVE-2015-7575", "CVE-2016-1523", "CVE-2016-1930", "CVE-2016-1935");
  script_tag(name:"creation_date", value:"2016-03-10 05:17:04 +0000 (Thu, 10 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-2904-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2904-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2904-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2904-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Karthikeyan Bhargavan and Gaetan Leurent discovered that NSS incorrectly
allowed MD5 to be used for TLS 1.2 connections. If a remote attacker were
able to perform a machine-in-the-middle attack, this flaw could be exploited to
view sensitive information. (CVE-2015-7575)

Yves Younan discovered that graphite2 incorrectly handled certain malformed
fonts. If a user were tricked into opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2016-1523)

Bob Clary, Christian Holler, Nils Ohlmeier, Gary Kwong, Jesse Ruderman,
Carsten Book, and Randell Jesup discovered multiple memory safety issues
in Thunderbird. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit these
to cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking Thunderbird. (CVE-2016-1930)

Aki Helin discovered a buffer overflow when rendering WebGL content in
some circumstances. If a user were tricked in to opening a specially
crafted website in a browsing context, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2016-1935)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
