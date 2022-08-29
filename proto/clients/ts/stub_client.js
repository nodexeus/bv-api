"use strict";
exports.__esModule = true;
exports.GrpcClient = void 0;
var Authentication_serviceServiceClientPb_1 = require("./out/Authentication_serviceServiceClientPb");
var authentication_service_pb_1 = require("./out/authentication_service_pb");
var common_pb_1 = require("./out/common_pb");
var uuid_1 = require("uuid");
var Billing_serviceServiceClientPb_1 = require("./out/Billing_serviceServiceClientPb");
var Dashboard_serviceServiceClientPb_1 = require("./out/Dashboard_serviceServiceClientPb");
var Fe_host_serviceServiceClientPb_1 = require("./out/Fe_host_serviceServiceClientPb");
var Host_provision_serviceServiceClientPb_1 = require("./out/Host_provision_serviceServiceClientPb");
var Node_serviceServiceClientPb_1 = require("./out/Node_serviceServiceClientPb");
var Organization_serviceServiceClientPb_1 = require("./out/Organization_serviceServiceClientPb");
var Update_serviceServiceClientPb_1 = require("./out/Update_serviceServiceClientPb");
var User_serviceServiceClientPb_1 = require("./out/User_serviceServiceClientPb");
var billing_service_pb_1 = require("./out/billing_service_pb");
var google_protobuf_timestamp_pb = require("google-protobuf/google/protobuf/timestamp_pb");
var google_protobuf_any_pb = require("google-protobuf/google/protobuf/any_pb");
var dashboard_service_pb_1 = require("./out/dashboard_service_pb");
var fe_host_service_pb_1 = require("./out/fe_host_service_pb");
var Name = common_pb_1.KPI.Name;
var HostStatus = common_pb_1.Host.HostStatus;
var NodeType = common_pb_1.Node.NodeType;
var NodeStatus = common_pb_1.Node.NodeStatus;
var host_provision_service_pb_1 = require("./out/host_provision_service_pb");
var node_service_pb_1 = require("./out/node_service_pb");
var organization_service_pb_1 = require("./out/organization_service_pb");
var user_service_pb_1 = require("./out/user_service_pb");
var update_service_pb_1 = require("./out/update_service_pb");
var GrpcClient = /** @class */ (function () {
    function GrpcClient(host) {
        // TODO: uncomment when backend services are available
        // this.initClients(host);
        this.token = "";
    }
    GrpcClient.prototype.setTokenValue = function (token) {
        this.token = token;
    };
    /**
     * Initialize all gRPC clients
     */
    GrpcClient.prototype.initClients = function (host) {
        this.authentication = new Authentication_serviceServiceClientPb_1.AuthenticationServiceClient(host, null, null);
        this.billing = new Billing_serviceServiceClientPb_1.BillingServiceClient(host, null, null);
        this.dashboard = new Dashboard_serviceServiceClientPb_1.DashboardServiceClient(host, null, null);
        this.host = new Fe_host_serviceServiceClientPb_1.HostServiceClient(host, null, null);
        this.host_provision = new Host_provision_serviceServiceClientPb_1.HostProvisionServiceClient(host, null, null);
        this.node = new Node_serviceServiceClientPb_1.NodeServiceClient(host, null, null);
        this.organization = new Organization_serviceServiceClientPb_1.OrganizationServiceClient(host, null, null);
        this.update = new Update_serviceServiceClientPb_1.UpdateServiceClient(host, null, null);
        this.user = new User_serviceServiceClientPb_1.UserServiceClient(host, null, null);
    };
    GrpcClient.prototype.getApiToken = function () {
        var api_token = new common_pb_1.ApiToken();
        // TODO: base64 encode token value
        api_token.setValue(this.token);
        return api_token;
    };
    GrpcClient.prototype.getDummyMeta = function () {
        var uuid = new common_pb_1.Uuid();
        uuid.setValue((0, uuid_1.v4)());
        var meta = new common_pb_1.ResponseMeta();
        meta.setStatus(common_pb_1.ResponseMeta.Status.SUCCESS);
        meta.setOriginRequestId(uuid);
        return meta;
    };
    GrpcClient.prototype.getDummyNode = function () {
        var node = new common_pb_1.Node();
        node.setId((0, uuid_1.v4)());
        node.setOrgId((0, uuid_1.v4)());
        node.setBlockchainId((0, uuid_1.v4)());
        node.setName("lorem-node");
        node.setGroupsList(["group-one"]);
        node.setVersion("0.1.0");
        node.setIp("127.0.0.1");
        node.setType(NodeType.NODE);
        node.setAddress("0x999999999");
        node.setWalletAddress("0x000000001");
        node.setBlockHeight(12121112);
        node.setNodeData("some-blob");
        node.setCreatedAt(this.getDummyTimestamp());
        node.setUpdatedAt(this.getDummyTimestamp());
        node.setStatus(NodeStatus.PROCESSING);
        return node;
    };
    GrpcClient.prototype.getDummyHost = function () {
        var host = new common_pb_1.Host();
        host.setId((0, uuid_1.v4)());
        host.setOrgId((0, uuid_1.v4)());
        host.setName("lorem-ipsum");
        host.setVersion("0.1.0");
        host.setLocation("Djibouti");
        host.setCpuCount(8);
        host.setMemSize(32);
        host.setDiskSize(2048);
        host.setOs("Darwin");
        host.setOsVersion("21.6.0 Darwin Kernel Version 21.6.");
        host.setIp("127.0.0.1");
        host.addNodes(this.getDummyNode());
        host.setStatus(HostStatus.CREATING);
        host.setCreatedAt(this.getDummyTimestamp());
        return host;
    };
    GrpcClient.prototype.getDummyTimestamp = function () {
        var fromdate = new Date();
        var timestamp = new google_protobuf_timestamp_pb.Timestamp();
        timestamp.setSeconds(fromdate.getSeconds());
        timestamp.setNanos(0);
        return timestamp;
    };
    /* Authentication service */
    GrpcClient.prototype.login = function (email, pwd) {
        console.debug("Using \"".concat(email, "\" => \"").concat(pwd, "\" for login"));
        if (email === "user@test.com") {
            var response = new authentication_service_pb_1.LoginUserResponse();
            response.setMeta(this.getDummyMeta());
            response.setToken(this.getApiToken());
            return response;
        }
        else {
            return {
                code: "Unauthenticated",
                message: "invalid authentication credentials\n\n",
                metadata: {
                    headers: {
                        "content-type": "application/grpc",
                        "date": "Fri, 26 Aug 2022 17:55:33 GMT",
                        "content-length": "0"
                    }
                },
                source: "None"
            };
        }
    };
    GrpcClient.prototype.refresh = function () {
        var response = new authentication_service_pb_1.RefreshTokenResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    /* Billing service */
    GrpcClient.prototype.createBill = function () {
        var bill = new common_pb_1.Bill();
        bill.setId((0, uuid_1.v4)());
        bill.setPdfUrl("/some/url.pdf");
        bill.setCreatedAt(this.getDummyTimestamp());
        bill.setTaxNumber("tax-number");
        bill.setReceiverName("Max Mustermann");
        bill.setReceiverAddress("Bondstreet 1a, 12312 Djibouti");
        bill.setTaxRate(0.2);
        bill.setNetAmount(100.0);
        bill.setGrossAmount(120.0);
        var response = new billing_service_pb_1.CreateBillResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    /* Dashboard service */
    GrpcClient.prototype.getDashboardKPIs = function () {
        var kpi = new common_pb_1.KPI();
        kpi.setName(Name.NODES);
        kpi.setValue(new google_protobuf_any_pb.Any());
        var response = new dashboard_service_pb_1.DashboardKpiResponse();
        response.setMeta(this.getDummyMeta());
        response.addValues(kpi);
        return response;
    };
    /* Host service */
    GrpcClient.prototype.getHosts = function () {
        var response = new fe_host_service_pb_1.GetHostsResponse();
        response.setMeta(this.getDummyMeta());
        response.addHosts(this.getDummyHost());
        return response;
    };
    GrpcClient.prototype.createHost = function () {
        var response = new fe_host_service_pb_1.CreateHostResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    GrpcClient.prototype.updateHost = function () {
        var response = new fe_host_service_pb_1.UpdateHostResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    GrpcClient.prototype.deleteHost = function () {
        var response = new fe_host_service_pb_1.DeleteHostResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    /* Host provision service */
    GrpcClient.prototype.getHostProvision = function () {
        var provision = new common_pb_1.HostProvision();
        provision.setId("abcdefgh");
        provision.setOrgId((0, uuid_1.v4)());
        provision.setHostId((0, uuid_1.v4)());
        provision.setInstallCmd("install cmd");
        provision.setCreatedAt(this.getDummyTimestamp());
        provision.setClaimedAt(this.getDummyTimestamp());
        var response = new host_provision_service_pb_1.GetHostProvisionResponse();
        response.setMeta(this.getDummyMeta());
        response.setHostProvision(provision);
        return response;
    };
    GrpcClient.prototype.createHostProvision = function () {
        var response = new host_provision_service_pb_1.CreateHostProvisionResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    /* Node service */
    GrpcClient.prototype.getNode = function () {
        var response = new node_service_pb_1.GetNodeResponse();
        response.setMeta(this.getDummyMeta());
        response.setNodesList([this.getDummyNode()]);
        return response;
    };
    GrpcClient.prototype.createNode = function () {
        var response = new node_service_pb_1.CreateNodeResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    GrpcClient.prototype.updateNode = function () {
        var response = new node_service_pb_1.UpdateNodeResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    /* Organization service */
    GrpcClient.prototype.getOrganizations = function () {
        var organization = new common_pb_1.Organization();
        organization.setId((0, uuid_1.v4)());
        organization.setName("ThisGroup");
        organization.setPersonal(true);
        organization.setMemberCount(1);
        organization.setCreatedAt(this.getDummyTimestamp());
        organization.setUpdatedAt(this.getDummyTimestamp());
        var response = new organization_service_pb_1.GetOrganizationsResponse();
        response.setMeta(this.getDummyMeta());
        response.setOrganizationsList([organization]);
        return response;
    };
    GrpcClient.prototype.createOrganization = function () {
        var response = new organization_service_pb_1.CreateOrganizationResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    GrpcClient.prototype.updateOrganization = function () {
        var response = new organization_service_pb_1.UpdateOrganizationResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    GrpcClient.prototype.deleteOrganization = function () {
        var response = new organization_service_pb_1.DeleteOrganizationResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    /* User service */
    GrpcClient.prototype.getUser = function () {
        var user = new common_pb_1.User();
        user.setId((0, uuid_1.v4)());
        user.setFirstName("max");
        user.setLastName("Mustermann");
        user.setEmail("max@mustermann.at");
        user.setCreatedAt(this.getDummyTimestamp());
        user.setUpdatedAt(this.getDummyTimestamp());
        var response = new user_service_pb_1.GetUserResponse();
        response.setMeta(this.getDummyMeta());
        response.setUser(user);
        return response;
    };
    GrpcClient.prototype.createUser = function () {
        var response = new user_service_pb_1.CreateUserResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    GrpcClient.prototype.upsertConfiguration = function () {
        var response = new user_service_pb_1.UpsertConfigurationResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    GrpcClient.prototype.getConfiguration = function () {
        var response = new user_service_pb_1.GetConfigurationResponse();
        response.setMeta(this.getDummyMeta());
        return response;
    };
    /* Update service */
    GrpcClient.prototype.getUpdates = function () {
        var update = new common_pb_1.InfoUpdate();
        update.setNode(this.getDummyNode());
        var response = new update_service_pb_1.GetUpdatesResponse();
        response.setMeta(this.getDummyMeta());
        response.setUpdate(update);
        return [response];
    };
    return GrpcClient;
}());
exports.GrpcClient = GrpcClient;
