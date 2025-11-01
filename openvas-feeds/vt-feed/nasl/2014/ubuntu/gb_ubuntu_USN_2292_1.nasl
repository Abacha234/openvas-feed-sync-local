# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841894");
  script_cve_id("CVE-2014-3230");
  script_tag(name:"creation_date", value:"2014-07-21 11:16:57 +0000 (Mon, 21 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-06 15:23:00 +0000 (Thu, 06 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-2292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2292-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2292-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liblwp-protocol-https-perl' package(s) announced via the USN-2292-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the LWP::Protocol::https perl module incorrectly
disabled peer certificate verification completely when only hostname
verification was requested to be disabled. If a remote attacker were able
to perform a machine-in-the-middle attack, this flaw could possibly be
exploited in certain scenarios to alter or compromise confidential
information in applications that used the LWP::Protocol::https module.");

  script_tag(name:"affected", value:"'liblwp-protocol-https-perl' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
