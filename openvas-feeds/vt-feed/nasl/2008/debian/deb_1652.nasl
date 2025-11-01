# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61774");
  script_cve_id("CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_tag(name:"creation_date", value:"2008-11-01 00:55:10 +0000 (Sat, 01 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1652)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1652");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1652");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.9' package(s) announced via the DSA-1652 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Ruby language, which may lead to denial of service and other security problems. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-3655

Keita Yamaguchi discovered that several safe level restrictions are insufficiently enforced.

CVE-2008-3656

Christian Neukirchen discovered that the WebRick module uses inefficient algorithms for HTTP header splitting, resulting in denial of service through resource exhaustion.

CVE-2008-3657

It was discovered that the dl module doesn't perform taintness checks.

CVE-2008-3790

Luka Treiber and Mitja Kolsek discovered that recursively nested XML entities can lead to denial of service through resource exhaustion in rexml.

CVE-2008-3905

Tanaka Akira discovered that the resolv module uses sequential transaction IDs and a fixed source port for DNS queries, which makes it more vulnerable to DNS spoofing attacks.

For the stable distribution (etch), these problems have been fixed in version 1.9.0+20060609-1etch3. Packages for arm will be provided later.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.2-6.

We recommend that you upgrade your ruby1.9 packages.");

  script_tag(name:"affected", value:"'ruby1.9' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);