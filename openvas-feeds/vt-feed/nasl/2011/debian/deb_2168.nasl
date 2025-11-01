# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69001");
  script_cve_id("CVE-2011-0430", "CVE-2011-0431");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2168");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2168");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-2168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered the distributed filesystem AFS:

CVE-2011-0430

Andrew Deason discovered that a double free in the Rx server process could lead to denial of service or the execution of arbitrary code.

CVE-2011-0431

It was discovered that insufficient error handling in the kernel module could lead to denial of service.

For the oldstable distribution (lenny), this problem has been fixed in version 1.4.7.dfsg1-6+lenny4. Due to a technical problem with the buildd infrastructure the update is not yet available, but will be installed into the archive soon.

For the stable distribution (squeeze), this problem has been fixed in version 1.4.12.1+dfsg-4.

For the unstable distribution (sid), this problem has been fixed in version 1.4.14+dfsg-1.

We recommend that you upgrade your openafs packages. Note that in order to apply this security update, you must rebuild the OpenAFS kernel module.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);