"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
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
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                this.authentication = new Authentication_serviceServiceClientPb_1.AuthenticationServiceClient(host, null, null);
                this.billing = new Billing_serviceServiceClientPb_1.BillingServiceClient(host, null, null);
                this.dashboard = new Dashboard_serviceServiceClientPb_1.DashboardServiceClient(host, null, null);
                this.host = new Fe_host_serviceServiceClientPb_1.HostServiceClient(host, null, null);
                this.host_provision = new Host_provision_serviceServiceClientPb_1.HostProvisionServiceClient(host, null, null);
                this.node = new Node_serviceServiceClientPb_1.NodeServiceClient(host, null, null);
                this.organization = new Organization_serviceServiceClientPb_1.OrganizationServiceClient(host, null, null);
                this.update = new Update_serviceServiceClientPb_1.UpdateServiceClient(host, null, null);
                this.user = new User_serviceServiceClientPb_1.UserServiceClient(host, null, null);
                return [2 /*return*/];
            });
        });
    };
    GrpcClient.prototype.getApiToken = function () {
        var api_token = new common_pb_1.ApiToken();
        // TODO: base64 encode token value
        api_token.setValue(this.token);
        return api_token;
    };
    GrpcClient.prototype.getDummyMeta = function () {
        var meta = new common_pb_1.ResponseMeta();
        meta.setStatus(common_pb_1.ResponseMeta.Status.SUCCESS);
        meta.setOriginRequestId(this.getDummyUuid());
        return meta;
    };
    GrpcClient.prototype.getDummyUuid = function () {
        var uuid = new common_pb_1.Uuid();
        uuid.setValue((0, uuid_1.v4)());
        return uuid;
    };
    GrpcClient.prototype.getDummyNode = function () {
        var node = new common_pb_1.Node();
        node.setId(this.getDummyUuid());
        node.setOrgId(this.getDummyUuid());
        node.setBlockchainId(this.getDummyUuid());
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
        host.setId(this.getDummyUuid());
        host.setOrgId(this.getDummyUuid());
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
    // @ts-ignore
    GrpcClient.prototype.login = function (email, pwd) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                console.debug("Using \"".concat(email, "\" => \"").concat(pwd, "\" for login"));
                if (email === "user@test.com") {
                    response = new authentication_service_pb_1.LoginUserResponse();
                    response.setMeta(this.getDummyMeta());
                    response.setToken(this.getApiToken());
                    return [2 /*return*/, response];
                }
                else {
                    return [2 /*return*/, {
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
                        }];
                }
                return [2 /*return*/];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.refresh = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new authentication_service_pb_1.RefreshTokenResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    /* Billing service */
    GrpcClient.prototype.createBill = function () {
        var bill = new common_pb_1.Bill();
        bill.setId("some-bill-id");
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
    // @ts-ignore
    GrpcClient.prototype.getDashboardKPIs = function () {
        return __awaiter(this, void 0, void 0, function () {
            var kpi, response;
            return __generator(this, function (_a) {
                kpi = new common_pb_1.KPI();
                kpi.setName(Name.NODES);
                kpi.setValue(new google_protobuf_any_pb.Any());
                response = new dashboard_service_pb_1.DashboardKpiResponse();
                response.setMeta(this.getDummyMeta());
                response.addValues(kpi);
                return [2 /*return*/, response];
            });
        });
    };
    /* Host service */
    // @ts-ignore
    GrpcClient.prototype.getHosts = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new fe_host_service_pb_1.GetHostsResponse();
                response.setMeta(this.getDummyMeta());
                response.addHosts(this.getDummyHost());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.createHost = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new fe_host_service_pb_1.CreateHostResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.updateHost = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new fe_host_service_pb_1.UpdateHostResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.deleteHost = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new fe_host_service_pb_1.DeleteHostResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    /* Host provision service */
    // @ts-ignore
    GrpcClient.prototype.getHostProvision = function () {
        return __awaiter(this, void 0, void 0, function () {
            var provision, response;
            return __generator(this, function (_a) {
                provision = new common_pb_1.HostProvision();
                provision.setId("abcdefgh");
                provision.setOrgId(this.getDummyUuid());
                provision.setHostId(this.getDummyUuid());
                provision.setInstallCmd("install cmd");
                provision.setCreatedAt(this.getDummyTimestamp());
                provision.setClaimedAt(this.getDummyTimestamp());
                response = new host_provision_service_pb_1.GetHostProvisionResponse();
                response.setMeta(this.getDummyMeta());
                response.setHostProvision(provision);
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.createHostProvision = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new host_provision_service_pb_1.CreateHostProvisionResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    /* Node service */
    // @ts-ignore
    GrpcClient.prototype.getNode = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new node_service_pb_1.GetNodeResponse();
                response.setMeta(this.getDummyMeta());
                response.setNodesList([this.getDummyNode()]);
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.createNode = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new node_service_pb_1.CreateNodeResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.updateNode = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new node_service_pb_1.UpdateNodeResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    /* Organization service */
    // @ts-ignore
    GrpcClient.prototype.getOrganizations = function () {
        return __awaiter(this, void 0, void 0, function () {
            var organization, response;
            return __generator(this, function (_a) {
                organization = new common_pb_1.Organization();
                organization.setId(this.getDummyUuid());
                organization.setName("ThisGroup");
                organization.setPersonal(true);
                organization.setMemberCount(1);
                organization.setCreatedAt(this.getDummyTimestamp());
                organization.setUpdatedAt(this.getDummyTimestamp());
                response = new organization_service_pb_1.GetOrganizationsResponse();
                response.setMeta(this.getDummyMeta());
                response.setOrganizationsList([organization]);
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.createOrganization = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new organization_service_pb_1.CreateOrganizationResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.updateOrganization = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new organization_service_pb_1.UpdateOrganizationResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.deleteOrganization = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new organization_service_pb_1.DeleteOrganizationResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    /* User service */
    // @ts-ignore
    GrpcClient.prototype.getUser = function () {
        return __awaiter(this, void 0, void 0, function () {
            var user, response;
            return __generator(this, function (_a) {
                user = new common_pb_1.User();
                user.setId(this.getDummyUuid());
                user.setFirstName("max");
                user.setLastName("Mustermann");
                user.setEmail("max@mustermann.at");
                user.setCreatedAt(this.getDummyTimestamp());
                user.setUpdatedAt(this.getDummyTimestamp());
                response = new user_service_pb_1.GetUserResponse();
                response.setMeta(this.getDummyMeta());
                response.setUser(user);
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.createUser = function (user) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                console.log("using user data: ".concat(user));
                response = new user_service_pb_1.CreateUserResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.upsertConfiguration = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new user_service_pb_1.UpsertConfigurationResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    // @ts-ignore
    GrpcClient.prototype.getConfiguration = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                response = new user_service_pb_1.GetConfigurationResponse();
                response.setMeta(this.getDummyMeta());
                return [2 /*return*/, response];
            });
        });
    };
    /* Update service */
    // @ts-ignore
    GrpcClient.prototype.getUpdates = function () {
        return __awaiter(this, void 0, void 0, function () {
            var update, response;
            return __generator(this, function (_a) {
                update = new common_pb_1.InfoUpdate();
                update.setNode(this.getDummyNode());
                response = new update_service_pb_1.GetUpdatesResponse();
                response.setMeta(this.getDummyMeta());
                response.setUpdate(update);
                return [2 /*return*/, [response]];
            });
        });
    };
    return GrpcClient;
}());
exports.GrpcClient = GrpcClient;
