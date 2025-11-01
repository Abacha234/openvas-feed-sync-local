# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892386");
  script_cve_id("CVE-2019-20919", "CVE-2020-14392", "CVE-2020-14393");
  script_tag(name:"creation_date", value:"2020-09-29 03:00:44 +0000 (Tue, 29 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 16:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-2386)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2386");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2386");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libdbi-perl");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libdbi-perl' package(s) announced via the DLA-2386 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Perl5 Database Interface (DBI). An attacker could trigger a denial-of-service (DoS) and possibly execute arbitrary code.

CVE-2019-20919

The hv_fetch() documentation requires checking for NULL and the code does that. But, shortly thereafter, it calls SvOK(profile), causing a NULL pointer dereference.

CVE-2020-14392

An untrusted pointer dereference flaw was found in Perl-DBI. A local attacker who is able to manipulate calls to dbd_db_login6_sv() could cause memory corruption, affecting the service's availability.

CVE-2020-14393

A buffer overflow on via an overlong DBD class name in dbih_setup_handle function may lead to data be written past the intended limit.

For Debian 9 stretch, these problems have been fixed in version 1.636-1+deb9u1.

We recommend that you upgrade your libdbi-perl packages.

For the detailed security status of libdbi-perl please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libdbi-perl' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);