"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const rsa = __importStar(require("../controllers/rsa.controller"));
const rsaRouter = (0, express_1.Router)();
rsaRouter.route('/generateKeys')
    .get(rsa.generateBothKeys);
rsaRouter.route('/pubK_S')
    .get(rsa.getServerPubK);
rsaRouter.route('/sign')
    .get(rsa.signMsg);
rsaRouter.route('/vote')
    .post(rsa.vote);
rsaRouter.route('/check')
    .get(rsa.checkVotes);
rsaRouter.route('/check')
    .post(rsa.checkVotes);
rsaRouter.route('/paillierkeys')
    .post(rsa.getPaillier);
rsaRouter.route('/paillierkeys')
    .get(rsa.getPaillier);
exports.default = rsaRouter;
//# sourceMappingURL=rsa.route.js.map