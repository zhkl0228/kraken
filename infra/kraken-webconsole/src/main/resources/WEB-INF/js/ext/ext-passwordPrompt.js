Ext.MessageBox=function(){var dlg,opt,mask,waitTimer;var bodyEl,msgEl,textboxEl,textareaEl,passwordEl,progressBar,pp,iconEl,spacerEl;var buttons,activeTextEl,bwidth,iconCls='';var handleButton=function(button){if(dlg.isVisible()){dlg.hide();handleHide();Ext.callback(opt.fn,opt.scope||window,[button,activeTextEl.dom.value,opt],1);}};var handleHide=function(){if(opt && opt.cls){dlg.el.removeClass(opt.cls);}progressBar.reset();};var handleEsc=function(d,k,e){if(opt && opt.closable !==false){dlg.hide();handleHide();}if(e){e.stopEvent();}};var updateButtons=function(b){var width=0;if(!b){buttons["ok"].hide();buttons["cancel"].hide();buttons["yes"].hide();buttons["no"].hide();return width;}dlg.footer.dom.style.display='';for(var k in buttons){if(typeof buttons[k] !="function"){if(b[k]){buttons[k].show();buttons[k].setText(typeof b[k]=="string"?b[k]:Ext.MessageBox.buttonText[k]);width+=buttons[k].el.getWidth()+15;}else{buttons[k].hide();}}}return width;};return{getDialog:function(titleText){if(!dlg){dlg=new Ext.Window({autoCreate:true,title:titleText,resizable:false,constrain:true,constrainHeader:true,minimizable:false,maximizable:false,stateful:false,modal:true,shim:true,buttonAlign:"center",width:400,height:100,minHeight:80,plain:true,footer:true,closable:true,close:function(){if(opt && opt.buttons && opt.buttons.no && !opt.buttons.cancel){handleButton("no");}else{handleButton("cancel");}}});buttons={};var bt=this.buttonText;buttons["ok"]=dlg.addButton(bt["ok"],handleButton.createCallback("ok"));buttons["yes"]=dlg.addButton(bt["yes"],handleButton.createCallback("yes"));buttons["no"]=dlg.addButton(bt["no"],handleButton.createCallback("no"));buttons["cancel"]=dlg.addButton(bt["cancel"],handleButton.createCallback("cancel"));buttons["ok"].hideMode=buttons["yes"].hideMode=buttons["no"].hideMode=buttons["cancel"].hideMode='offsets';dlg.render(document.body);dlg.getEl().addClass('x-window-dlg');mask=dlg.mask;bodyEl=dlg.body.createChild({html:'<div class="ext-mb-icon"></div><div class="ext-mb-content"><span class="ext-mb-text"></span><br/><div class="ext-mb-fix-cursor"><input type="text" class="ext-mb-input"/><textarea class="ext-mb-textarea"></textarea><input type="password" class="ext-mb-input"/></div></div>'});iconEl=Ext.get(bodyEl.dom.firstChild);var contentEl=bodyEl.dom.childNodes[1];msgEl=Ext.get(contentEl.firstChild);textboxEl=Ext.get(contentEl.childNodes[2].firstChild);textboxEl.enableDisplayMode();textboxEl.addKeyListener([10,13],function(){if(dlg.isVisible() && opt && opt.buttons){if(opt.buttons.ok){handleButton("ok");}else if(opt.buttons.yes){handleButton("yes");}}});textareaEl=Ext.get(contentEl.childNodes[2].childNodes[1]);textareaEl.enableDisplayMode();passwordEl=Ext.get(contentEl.childNodes[2].childNodes[2]);passwordEl.enableDisplayMode();passwordEl.addKeyListener([10,13],function(){if(dlg.isVisible() && opt && opt.buttons){if(opt.buttons.ok){handleButton("ok");}else if(opt.buttons.yes){handleButton("yes");}}});progressBar=new Ext.ProgressBar({renderTo:bodyEl});bodyEl.createChild({cls:'x-clear'});}return dlg;},updateText:function(text){if(!dlg.isVisible() && !opt.width){dlg.setSize(this.maxWidth,100);}msgEl.update(text||'&#160;');var iw=iconCls !=''?(iconEl.getWidth()+iconEl.getMargins('lr')):0;var mw=msgEl.getWidth()+msgEl.getMargins('lr');var fw=dlg.getFrameWidth('lr');var bw=dlg.body.getFrameWidth('lr');if(Ext.isIE && iw>0){iw+=3;}var w=Math.max(Math.min(opt.width||iw+mw+fw+bw,this.maxWidth),Math.max(opt.minWidth||this.minWidth,bwidth||0));if(opt.prompt===true){activeTextEl.setWidth(w-iw-fw-bw);}if(opt.progress===true||opt.wait===true){progressBar.setSize(w-iw-fw-bw);}if(Ext.isIE && w==bwidth){w+=4;}dlg.setSize(w,'auto').center();return this;},updateProgress:function(value,progressText,msg){progressBar.updateProgress(value,progressText);if(msg){this.updateText(msg);}return this;},isVisible:function(){return dlg && dlg.isVisible();},hide:function(){var proxy=dlg?dlg.activeGhost:null;if(this.isVisible()||proxy){dlg.hide();handleHide();if(proxy){dlg.unghost(false,false);}}return this;},show:function(options){if(this.isVisible()){this.hide();}opt=options;var d=this.getDialog(opt.title||"&#160;");d.setTitle(opt.title||"&#160;");var allowClose=(opt.closable !==false && opt.progress !==true && opt.wait !==true);d.tools.close.setDisplayed(allowClose);activeTextEl=textboxEl;opt.prompt=opt.prompt||(opt.multiline?true:false);if(opt.prompt){if(opt.multiline){textboxEl.hide();passwordEl.hide();textareaEl.show();textareaEl.setHeight(typeof opt.multiline=="number"?opt.multiline:this.defaultTextHeight);activeTextEl=textareaEl;}else if(opt.password){passwordEl.show();textboxEl.hide();textareaEl.hide();activeTextEl=passwordEl;}else{textboxEl.show();textareaEl.hide();passwordEl.hide();}}else{textboxEl.hide();textareaEl.hide();passwordEl.hide();}activeTextEl.dom.value=opt.value||"";if(opt.prompt){d.focusEl=activeTextEl;}else{var bs=opt.buttons;var db=null;if(bs && bs.ok){db=buttons["ok"];}else if(bs && bs.yes){db=buttons["yes"];}if(db){d.focusEl=db;}}if(opt.iconCls){d.setIconClass(opt.iconCls);}this.setIcon(opt.icon);if(opt.cls){d.el.addClass(opt.cls);}d.proxyDrag=opt.proxyDrag===true;d.modal=opt.modal !==false;d.mask=opt.modal !==false?mask:false;d.on('show',function(){d.keyMap.setDisabled(allowClose !==true);d.doLayout();this.setIcon(opt.icon);bwidth=updateButtons(opt.buttons);progressBar.setVisible(opt.progress===true||opt.wait===true);this.updateProgress(0,opt.progressText);this.updateText(opt.msg);if(opt.wait===true){progressBar.wait(opt.waitConfig);}},this,{single:true});if(!d.isVisible()){document.body.appendChild(dlg.el.dom);d.setAnimateTarget(opt.animEl);d.show(opt.animEl);}return this;},setIcon:function(icon){if(icon && icon !=''){iconEl.removeClass('x-hidden');iconEl.replaceClass(iconCls,icon);bodyEl.addClass('x-dlg-icon');iconCls=icon;}else{iconEl.replaceClass(iconCls,'x-hidden');bodyEl.removeClass('x-dlg-icon');iconCls='';}return this;},progress:function(title,msg,progressText){this.show({title:title,msg:msg,buttons:false,progress:true,closable:false,minWidth:this.minProgressWidth,progressText:progressText});return this;},wait:function(msg,title,config){this.show({title:title,msg:msg,buttons:false,closable:false,wait:true,modal:true,minWidth:this.minProgressWidth,waitConfig:config});return this;},alert:function(title,msg,fn,scope){this.show({title:title,msg:msg,buttons:this.OK,fn:fn,scope:scope});return this;},confirm:function(title,msg,fn,scope){this.show({title:title,msg:msg,buttons:this.YESNO,fn:fn,scope:scope,icon:this.QUESTION});return this;},prompt:function(title,msg,fn,scope,multiline,value){this.show({title:title,msg:msg,buttons:this.OKCANCEL,fn:fn,minWidth:250,scope:scope,prompt:true,multiline:multiline,value:value});return this;},passwordPrompt:function(title,msg,fn,scope,multiline,value){this.show({title:title,msg:msg,password:true,buttons:this.OKCANCEL,fn:fn,minWidth:250,scope:scope,prompt:true,multiline:multiline,value:value});return this;},OK:{ok:true},CANCEL:{cancel:true},OKCANCEL:{ok:true,cancel:true},YESNO:{yes:true,no:true},YESNOCANCEL:{yes:true,no:true,cancel:true},INFO:'ext-mb-info',WARNING:'ext-mb-warning',QUESTION:'ext-mb-question',ERROR:'ext-mb-error',defaultTextHeight:75,maxWidth:600,minWidth:110,minProgressWidth:250,buttonText:{ok:"OK",cancel:"Cancel",yes:"Yes",no:"No"}};}();Ext.Msg=Ext.MessageBox;