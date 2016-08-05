====================================
CoprHD FC, iSCSI and ScaleIO Drivers
====================================

Introduction
System requirements
Supported operations
Driver Options
Preparation
ISCSI driver notes
FC driver notes
ScaleIO driver notes
Consistency group configuration

Introduction
~~~~~~~~~~~~

CoprHD is an open source software defined storage controller and API platform.
It enables policy-based management and cloud automation of storage resources
for block, object and file storage providers.
For more details please see - http://coprhd.org/

EMC ViPR Controller is the commercial offering of CoprHD. These same volume
drivers can also be considered as EMC ViPR Controller Cinder drivers.


System requirements
~~~~~~~~~~~~~~~~~~~

CoprHD version 3.0 is required. Refer to the CoprHD documentation for
installation and configuration instructions.

If you are using these drivers to integrate with EMC ViPR Controller, use
EMC ViPR Controller 3.0


Supported operations
~~~~~~~~~~~~~~~~~~~~

The following operations are supported:

- Create volume
- Delete volume
- Attach volume
- Detach volume
- Create snapshot
- Delete snapshot
- Get Volume Stats
- Copy image to volume
- Copy volume to image
- Clone volume
- Create volume from snapshot
- Extend volume
- Retype volume
- Create consistency group
- Delete consistency group
- Update consistency group
- Create consistency group snapshot
- Delete consistency group snapshot


Driver Options
~~~~~~~~~~~~~~

.. table::

======================                =============                                                                       ===========
 Configuration Option                  Description                                                                         Mandatory
======================                =============                                                                       ===========
 volume_driver                         (String)Name of the Volume Driver                                                   Yes
 volume_backend_name                   (String)Backend name for the Driver Instance                                        Yes
 coprhd_hostname                       (String)Hostname for the CoprHD Instance                                            Yes                             
 coprhd_port                           (Integer)Port for the CoprHD Instance                                               Yes
 coprhd_username                       (String)Username for accessing the CoprHD Instance                                  Yes
 coprhd_password                       (String)Password for accessing the CoprHD Instance                                  Yes
 coprhd_tenant                         (String)Tenant to utilize within the CoprHD Instance                                Yes
 coprhd_project                        (String)Project to utilize within the CoprHD Instance                               Yes
 coprhd_varray                         (String)Virtual Array to utilize within the CoprHD Instance                         Yes
 coprhd_emulate_snapshot               (Boolean)True | False to indicate if the storage array in CoprHD is VMAX or VPLEX   No
 coprhd_scaleio_rest_gateway_host      (String)Rest Gateway IP or FQDN for Scaleio                                         No
 coprhd_scaleio_rest_gateway_port      (Integer)Rest Gateway Port for Scaleio                                              No
 coprhd_scaleio_rest_server_username   (String)Username for Rest Gateway                                                   No                                  
 coprhd_scaleio_rest_server_password   (String)Rest Gateway Password                                                       No
 scaleio_verify_server_certificate     (Boolean)Verify server certificate                                                  No
 scaleio_server_certificate_path       (String)Server certificate path                                                     No





Preparation
~~~~~~~~~~~

CoprHD
------

The CoprHD environment must meet specific configuration requirements to
support the OpenStack Cinder Driver.

- CoprHD users must be assigned a Tenant Administrator role or a Project
  Administrator role for the Project being used. CoprHD roles are configured
  by CoprHD Security Administrators.  Consult the CoprHD documentation for
  details.

- The following configuration must have been done by a CoprHD System
  Administrator, using the CoprHD UI, CoprHD API, or CoprHD CLI

  - CoprHD Virtual Array should have been created.
  - CoprHD Virtual Storage Pool should have been created.
  - Virtual Array designated for iSCSI driver must have an IP network created
    with appropriate IP storage ports.
  - Designated tenant for use.
  - Designated project for use.

Please note each backend can be used to manage one virtual array and one
virtual storage pool. However, the user can have multiple instances of CoprHD
Cinder Driver, sharing the same virtual array and virtual storage pool.

- A typical CoprHD virtual storage pool will have following values specified

  - Storage Type: Block
  - Provisioning Type: Thin
  - Protocol: iSCSI/Fibre Channel(FC)/ScaleIO
  - Multi-Volume Consistency: DISABLED OR ENABLED
  - Maximum Native Snapshots: A value greater than 0 allows the OpenStack user
    to take Snapshots.


CoprHD Drivers - Single Backend
-------------------------------

**Cinder.conf** 

Modify /etc/cinder/cinder.conf by adding the following lines,
substituting values for your environment:

.. code-block:: ini

    [coprhd-iscsi]
    volume_driver = cinder.volume.drivers.coprhd.iscsi.EMCCoprHDISCSIDriver
    volume_backend_name = coprhd-iscsi
    coprhd_hostname=<CoprHD-Host-Name>
    coprhd_port=4443
    coprhd_username=<username>
    coprhd_password=<password>
    coprhd_tenant=<CoprHD-Tenant-Name> 
    coprhd_project=<CoprHD-Project-Name>
    coprhd_varray=<CoprHD-Virtual-Array-Name>
    coprhd_emulate_snapshot= True or False, True if the CoprHD vpool has VMAX or VPLEX as the backing storage

Below fields are needed only for ScaleIO backend.

| coprhd_scaleio_rest_gateway_host=<IP or FQDN>
| coprhd_scaleio_rest_gateway_port=443
| coprhd_scaleio_rest_server_username=<username>
| coprhd_scaleio_rest_server_password=<password>
| scaleio_verify_server_certificate=True or False
| scaleio_server_certificate_path=<path-of-certificate-for-validation>

Also, add the above driver to the enabled_backends parameter::

  enabled_backends = coprhd-iscsi

Note 1: To utilize the Fibre Channel Driver, replace the volume_driver
line above with::

  volume_driver = cinder.volume.drivers.coprhd.fc.EMCCoprHDFCDriver

Note 2: To utilize the ScaleIO Driver, replace the volume_driver line above
with::

  volume_driver = cinder.volume.drivers.coprhd.fc.EMCCoprHDScaleIODriver

Note 3: Set coprhd_emulate_snapshot to True, if the CoprHD vpool has VMAX or
VPLEX as the backend storage. For these type of backend storages, when user
tries to create a snapshot, an actual volume gets created in the backend.

Modify the rpc_response_timeout value in /etc/cinder/cinder.conf to at least
5 minutes. If this entry does not already exist within the cinder.conf file,
please add it in the::

  [DEFAULT] section
  rpc_response_timeout=300

Now, restart the cinder-volume service.

**Volume Type Creation and Extra Specs**

Create OpenStack volume types with the openstack command::

  openstack volume type create  < typename>

Map the OpenStack volume type to the CoprHD Virtual Pool with the openstack
command::

  openstack volume type set <typename> --property CoprHD:VPOOL=<CoprHD-PoolName>

Map the volume type created to appropriate backend driver::

  openstack volume type set <typename> --property volume_backend_name=<VOLUME_BACKEND_DRIVER>


CoprHD Drivers - Multiple Backends
----------------------------------

**Cinder.conf**

Add/modify the following entries if you are planning to use multiple back-end drivers::

  enabled_backends=coprhddriver-iscsi,coprhddriver-fc, coprhddriver-scaleio

Add the following at the end of the file:

.. code-block:: ini

  [coprhddriver-iscsi]
  volume_driver=cinder.volume.drivers.coprhd.iscsi.EMCCoprHDISCSIDriver
  volume_backend_name=EMCCoprHDISCSIDriver
  coprhd_hostname=<CoprHD Host Name>
  coprhd_port=4443
  coprhd_username=<username>
  coprhd_password=<password>
  coprhd_tenant=<CoprHD-Tenant-Name>
  coprhd_project=<CoprHD-Project-Name>
  coprhd_varray=<CoprHD-Virtual-Array-Name>


  [coprhddriver-fc]
  volume_driver=cinder.volume.drivers.coprhd.fc.EMCCoprHDFCDriver
  volume_backend_name=EMCCoprHHDFCDriver
  coprhd_hostname=<CoprHD Host Name>
  coprhd_port=4443
  coprhd_username=<username>
  coprhd_password=<password>
  coprhd_tenant=<CoprHD-Tenant-Name>
  coprhd_project=<CoprHD-Project-Name>
  coprhd_varray=<CoprHD-Virtual-Array-Name>


  [coprhddriver-scaleio]
  volume_driver = cinder.volume.drivers.coprhd.scaleio.EMCCoprHDScaleIODriver
  volume_backend_name=EMCCoprHDScaleIODriver
  coprhd_hostname=<CoprHD Host Name>
  coprhd_port=4443
  coprhd_username=<username>
  coprhd_password=<password>
  coprhd_tenant=<CoprHD-Tenant-Name>
  coprhd_project=<CoprHD-Project-Name>
  coprhd_varray=<CoprHD-Virtual-Array-Name>
  coprhd_scaleio_rest_gateway_host=<ScaleIO Rest Gateway>
  coprhd_scaleio_rest_gateway_port=443
  coprhd_scaleio_rest_server_username=<rest gateway username>
  coprhd_scaleio_rest_server_password=<rest gateway password>
  scaleio_verify_server_certificate=True or False
  scaleio_server_certificate_path=<certificate path>


Restart the cinder-volume service.


**Volume Type Creation and Extra Specs**

Setup the volume-types and volume-type to volume-backend association::

  openstack volume type create "CoprHD High Performance ISCSI" 
  openstack volume type set "CoprHD High Performance ISCSI" --property  CoprHD:VPOOL="High Performance ISCSI"
  openstack volume type set "CoprHD High Performance ISCSI" --property  volume_backend_name= EMCCoprHDISCSIDriver

  openstack volume type create "CoprHD High Performance FC"
  openstack volume type set "CoprHD High Performance FC" --property  CoprHD:VPOOL="High Performance FC"
  openstack volume type set "CoprHD High Performance FC" --property  volume_backend_name= EMCCoprHDFCDriver

  openstack volume type create "CoprHD performance SIO"
  openstack volume type set "CoprHD performance SIO" --property  CoprHD:VPOOL="Scaled Perf"
  openstack volume type set "CoprHD performance SIO" --property  volume_backend_name= EMCCoprHDScaleIODriver


ISCSI driver notes
~~~~~~~~~~~~~~~~~~

* The openstack compute host must be added to the CoprHD along with its ISCSI
  initiator
* The ISCSI initiator must be associated with IP network on the CoprHD


FC driver notes
~~~~~~~~~~~~~~~

* The OpenStack compute host must be attached to a VSAN or fabric discovered
  by CoprHD
* There is no need to perform any SAN zoning operations. CoprHD will perform
  the necessary operations automatically as part of the provisioning process


ScaleIO driver notes
~~~~~~~~~~~~~~~~~~~~

* Please install the ScaleIO SDC on the openstack compute host
* The OpenStack compute host must be added as the SDC to the ScaleIO MDS
  using the below commands::

    /opt/emc/scaleio/sdc/bin/drv_cfg --add_mdm --ip List of MDM IPs(starting with primary MDM and separated by comma)
    Example: /opt/emc/scaleio/sdc/bin/drv_cfg --add_mdm --ip 10.247.78.45,10.247.78.46,10.247.78.47

Verify the above with the following command. It should list the above configuration.
/opt/emc/scaleio/sdc/bin/drv_cfg --query_mdms

This step has to be repeated whenever the SDC(openstack host in this case) is rebooted.


Consistency group configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To enable the support of consistency group and consistency group snapshot
operations, use a text editor to edit the file /etc/cinder/policy.json and
change the values of the below fields as specified. Upon editing the file,
restart the c-api service::

  "consistencygroup:create" : "",
  "consistencygroup:delete": "",
  "consistencygroup:get": "",
  "consistencygroup:get_all": "",
  "consistencygroup:update": "",
  "consistencygroup:create_cgsnapshot" : "group:nobody",
  "consistencygroup:delete_cgsnapshot": "group:nobody",
  "consistencygroup:get_cgsnapshot": "group:nobody",
  "consistencygroup:get_all_cgsnapshots": "group:nobody",


Names of resources in backend storage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All the resources like Volume, Consistency Group, Snapshot and Consistency
Group Snapshot will use the display name in openstack for naming in the
backend storage.