# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704267");
  script_cve_id("CVE-2018-14767");
  script_tag(name:"creation_date", value:"2018-08-07 22:00:00 +0000 (Tue, 07 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-04 21:29:00 +0000 (Thu, 04 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-4267)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4267");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4267");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/kamailio");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kamailio' package(s) announced via the DSA-4267 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Henning Westerholt discovered a flaw related to the To header processing in kamailio, a very fast, dynamic and configurable SIP server. Missing input validation in the build_res_buf_from_sip_req function could result in denial of service and potentially the execution of arbitrary code.

For the stable distribution (stretch), this problem has been fixed in version 4.4.4-2+deb9u2.

We recommend that you upgrade your kamailio packages.

For the detailed security status of kamailio please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'kamailio' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);