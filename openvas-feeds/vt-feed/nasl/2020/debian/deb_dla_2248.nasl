# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892248");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_tag(name:"creation_date", value:"2020-06-14 03:00:22 +0000 (Sun, 14 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 08:15:00 +0000 (Wed, 09 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-2248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2248");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2248");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'intel-microcode' package(s) announced via the DLA-2248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following CVE(s) were reported against src:intel-microcode.

CVE-2020-0543

A new domain bypass transient execution attack known as Special Register Buffer Data Sampling (SRBDS) has been found. This flaw allows data values from special internal registers to be leaked by an attacker able to execute code on any core of the CPU. An unprivileged, local attacker can use this flaw to infer values returned by affected instructions known to be commonly used during cryptographic operations that rely on uniqueness, secrecy, or both.

CVE-2020-0548

A flaw was found in Intel processors where a local attacker is able to gain information about registers used for vector calculations by observing register states from other processes running on the system. This results in a race condition where store buffers, which were not cleared, could be read by another process or a CPU sibling. The highest threat from this vulnerability is data confidentiality where an attacker could read arbitrary data as it passes through the processor.

CVE-2020-0549

A microarchitectural timing flaw was found on some Intel processors. A corner case exists where data in-flight during the eviction process can end up in the 'fill buffers' and not properly cleared by the MDS mitigations. The fill buffer contents (which were expected to be blank) can be inferred using MDS or TAA style attack methods to allow a local attacker to infer fill buffer values.

For Debian 8 Jessie, these problems have been fixed in version 3.20200609.2~deb8u1.

We recommend that you upgrade your intel-microcode packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);