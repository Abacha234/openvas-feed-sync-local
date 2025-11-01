# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856863");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-45142", "CVE-2023-47108", "CVE-2024-41110");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-10 19:15:16 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-12-18 05:00:45 +0000 (Wed, 18 Dec 2024)");
  script_name("openSUSE: Security Advisory for docker (SUSE-SU-2024:4360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4360-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5QN46RDSEXZFITMIFYI2BFRQ6NL6TXZB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker'
  package(s) announced via the SUSE-SU-2024:4360-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker fixes the following issues:

  * Add a new toggle file /etc/docker/suse-secrets-enable which allows users to
      disable the SUSEConnect integration with Docker (which creates special
      mounts in /run/secrets to allow container-suseconnect to authenticate
      containers with registries on registered hosts). bsc#1231348 bsc#1232999

  and restart Docker. Docker will output information on startup to tell you
  whether the SUSE secrets feature is enabled or not.

  * Disable docker-buildx builds for SLES. It turns out that build containers
      with docker-buildx don't currently get the SUSE secrets mounts applied,
      meaning that container-suseconnect doesn't work when building images.
      bsc#1233819

  * Remove DOCKER_NETWORK_OPTS from docker.service. This was removed from
      sysconfig a long time ago, and apparently this causes issues with systemd in
      some cases.

  * Allow a parallel docker-stable RPM to exists in repositories.


  * Allow users to disable SUSE secrets support by setting
      DOCKER_SUSE_SECRETS_ENABLE=0 in /etc/sysconfig/docker. (bsc#1231348)

  * Mark docker-buildx as required since classic 'docker build' has been
      deprecated since Docker 23.0. (bsc#1230331)

  * Import docker-buildx v0.16.2 as a subpackage. Previously this was a separate
      package, but with docker-stable it will be necessary to maintain the
      packages together and it makes more sense to have them live in the same OBS
      package. (bsc#1230333)

  * This update includes fixes for:

  * CVE-2024-41110. bsc#1228324

  * CVE-2023-47108. bsc#1217070 bsc#1229806

  * CVE-2023-45142. bsc#1228553 bsc#1229806

  * Update to Docker 26.1.4-ce.  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'docker' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
