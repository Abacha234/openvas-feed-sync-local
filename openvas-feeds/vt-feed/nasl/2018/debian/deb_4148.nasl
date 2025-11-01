# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704148");
  script_cve_id("CVE-2018-8828");
  script_tag(name:"creation_date", value:"2018-03-21 23:00:00 +0000 (Wed, 21 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4148)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4148");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4148");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/kamailio");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kamailio' package(s) announced via the DSA-4148 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alfred Farrugia and Sandro Gauci discovered an off-by-one heap overflow in the Kamailio SIP server which could result in denial of service and potentially the execution of arbitrary code.

For the oldstable distribution (jessie), this problem has been fixed in version 4.2.0-2+deb8u3.

For the stable distribution (stretch), this problem has been fixed in version 4.4.4-2+deb9u1.

We recommend that you upgrade your kamailio packages.

For the detailed security status of kamailio please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'kamailio' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);