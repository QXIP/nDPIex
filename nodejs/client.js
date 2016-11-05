"use strict"
/**
 * Created by yaodong.hyd on 2016/8/23.
 */
var WebSocketClient = require("websocket").client;

class BaseClient {
    constructor(serverAddress){
        this.client = new WebSocketClient();
        var self = this;
        this.client.on("connectFailed",function(error){
            console.log("connect failed : "+error.toString());
            self.handleConnectionFailed(error);
        });
        this.client.on("connect",function(connection){
            self.connection = connection;
            connection.on("error",function(error){
                console.log("connection error : "+error.toString());
                self.handleError(error);
            });

            connection.on("message",function(msg){
                if (msg.type == 'utf-8'){
                    self.handleStringMessage(msg);
                }else{
                    //TODO:handle other message
                }
            });

            connection.on('close',function(){
                console.log('connection closed');
                self.handleConnectionClose();
            });
        });
        this.client.connect(serverAddress,'echo-protocol');
    }

    sendString(msg){
        if (this.connection && this.connection.connected){
            this.connection.sendUTF(msg);
        }
    }

    handleConnectionFailed(){}

    handleStringMessage(msg){}

    handleError(error){}

    handleConnectionClose(){}
}

exports.BaseClient = BaseClient;
