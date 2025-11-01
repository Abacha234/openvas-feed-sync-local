# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844705");
  script_cve_id("CVE-2020-27194", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2020-11-11 04:01:06 +0000 (Wed, 11 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-11 13:15:00 +0000 (Tue, 11 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4626-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4626-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4626-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-4626-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon Scannell discovered that the bpf verifier in the Linux kernel did not
properly calculate register bounds for certain operations. A local attacker
could use this to expose sensitive information (kernel memory) or gain
administrative privileges. (CVE-2020-27194)

Moritz Lipp, Michael Schwarz, Andreas Kogler, David Oswald, Catherine
Easdon, Claudio Canella, and Daniel Gruss discovered that the Intel Running
Average Power Limit (RAPL) driver in the Linux kernel did not properly
restrict access to power data. A local attacker could possibly use this to
expose sensitive information. (CVE-2020-8694)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
