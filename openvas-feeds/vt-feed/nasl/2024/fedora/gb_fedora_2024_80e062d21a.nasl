# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886493");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2022-1996", "CVE-2022-24675", "CVE-2022-28327", "CVE-2022-27191", "CVE-2022-29526", "CVE-2022-30629", "CVE-2023-39325");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:30 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"creation_date", value:"2024-05-27 10:42:06 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for golang-gvisor (FEDORA-2024-80e062d21a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-80e062d21a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ODBY7RVMGZCBSTWF2OZGIZS57FNFUL67");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-gvisor'
  package(s) announced via the FEDORA-2024-80e062d21a advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gVisor is an open-source, OCI-compatible sandbox runtime that provides
a virtualized container environment. It runs containers with a new
user-space kernel, delivering a low overhead container security
solution for high-density applications.

gVisor integrates with Docker, containerd and Kubernetes, making it
easier to improve the security isolation of your containers while
still using familiar tooling. Additionally, gVisor supports a variety
of underlying mechanisms for intercepting application calls, allowing
it to run in diverse host environments, including cloud-hosted virtual
machines.");

  script_tag(name:"affected", value:"'golang-gvisor' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
