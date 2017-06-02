#!/usr/bin/python

# This software is provided under under Public Domain. See the accompanying
# license on https://sourceforge.net/projects/pyurlsnooper/ for more
# information.
#
__version__ = '$Id: pyurlsnooper-gtk.py,v 1.4 2010/02/01 18:50:00 drtrigon $'
#
# Simple URL packet sniffer.
#
# This packet sniffer uses the pcap library to listen for packets in
# transit over the specified interface. The returned packages can be
# filtered according to a BPF filter (see tcpdump(3) for further
# information on BPF filters). Look also at sniff.py from pcapy at
# http://oss.coresecurity.com/impacket/sniff.py
# http://oss.coresecurity.com/projects/pcapy.html
# http://oss.coresecurity.com/pcapy/doc/pt01.html
#
# Note that the user might need special permissions to be able to use pcap.
#
# Run this script:
#     linux: - open terminal/shell
#            - run "su -c 'python pyurlsnooper-gtk.py'" to execute the script with
#              root permissions
#   windows: - open command-line as administrator (to execute the script with
#              admin permissions)
#            - run "python pyurlsnooper-gtk.py"
#            OR
#            - right-click on this file and choose to run as admin
#
# Look also at README for further details.
#
# Search for:
#  URL Snooper (Windows)
#  pcapy, ImpactDecoder, ...
#
# SVN:
#  svn co https://pyurlsnooper.svn.sourceforge.net/svnroot/pyurlsnooper pyurlsnooper
#  svn update
#  svn add [new-file]
#  svn ci -m "comment"
#  svn ci -F msg	("comment" in file 'msg')


# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# Imports
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
#
# python standard modules
import sys, string, os, re, warnings, socket, PyLib, urlparse
from threading import Thread

# package capture modules
import pcapy
from pcapy import findalldevs, open_live
import impacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

# GTK, PyGTK, GLADE (GNOME) modules
try:				# all imports needed?!?!
	import pygtk
	pygtk.require('2.0')
	import gtk
	import gtk.glade
	import gobject
except:
	print "No GTK could be found! Under Windows, please install GTK together with pygtk, pygobject and pycairo."
	sys.exit()

# os dependent imports
imported = []
if	 (os.name == 'posix') or (os.name == 'mac'):
	import fcntl, struct
elif (os.name == 'nt'):
	try:					# optional (and very recommended)
		import wmi
		imported.append( "wmi" )
		print "'wmi' found and imported."
	except: pass
	try:					# optional (and recommended)
		import dnet
		imported.append( "dnet" )
		print "'dnet' found and imported."
	except: pass
else:	# 'os2', 'ce', 'java', 'riscos'
	pass


# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# Variables / Constants
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
#
# this regex should be improved, because it already caused some problems (e.g. on southpark.de, ...)
regex_links = re.compile("((https?|ftp|gopher|telnet|file|notes|ms-help|rtmpe?|rtsp):((//)|(\\\\))[\w\d:#%/;$()~_?\-=\\\.&!]*)")

dict_filter = {	'(all)':					'', 
		'Hypertext Transfer Protocol (http/https)':	'http', 
		'File Transfer Protocol (ftp)':			'ftp', 
		'Real Time Messaging Protocol (rtmp/rtmpe)':	'rtmp', 
		'Real-Time Streaming Protocol (rtsp)':		'rtsp', 
		'MP4 Media (.mp4)':				'.mp4', 
		'Shockwave Flash Media (.swf)':			'.swf', 
		'Flash Video Media (.flv)':			'.flv',
		'MP3 Media (.mp3)':				'.mp3', 
		'WAV Media (.wav)':				'.wav', 
}		# etc. (not complete yet!)

raw_path = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])), os.path.splitext(sys.argv[0])[0])

# 'ext' support on/off?
# It is not planned to develop this option further. This option is thought for the brave python programmers who
# read until here! You can use this trick to integrate PyURLSnooper with your own application by direct communication.
# This is also a permission safe way to process the results further, because of the other applications can be runned
# without root/admin rights.
ext_sup = False


# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# Classes
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
#
class SnifferThread(Thread):
	"""
	Main decoder/network sniffer class (running in separate thread).
	"""

	# initialization
	#
	def __init__(self, pcapObj):
		""" Query the type of the link and instantiate a decoder accordingly. """
		datalink = pcapObj.datalink()
		if pcapy.DLT_EN10MB == datalink:
			self.decoder = EthDecoder()
		elif pcapy.DLT_LINUX_SLL == datalink:
			self.decoder = LinuxSLLDecoder()
		else:
			raise Exception("Datalink type not supported: " % datalink)

		self.pcap = pcapObj
		self.buffer	= []			# init internal buffer
		self.quit	= False			# quit thread?
		Thread.__init__(self)

	def run(self):
		""" Sniff ad infinitum.
		    PacketHandler shall be invoked by pcap for every packet.
		    When returning with error, decide  """
		while not self.quit:
			try:
				self.pcap.loop(0, self.__packetHandler)
			except SystemExit:	# raised by '__packetHandler' to force quit
				pass
				# is there a direct (simpler?) way to force return from waiting 'self.pcap.loop' ?!?
			except:			# generic error
				#warnings.warn( "%s %s" % sys.exc_info()[0:2] )
				#print "\n".join(inspect.getframeinfo(sys.exc_info()[2]).code_context)
				#print "".join([ 'File "%s", line %i, in %s (%s)\n%s\n' % (f[1:4]+("\n".join(f[4]),)) for f in inspect.getinnerframes(sys.exc_info()[2]) ])
				warnings.warn( "\n".join(PyLib.tb_info()[2]) )
				sys.exc_clear()

	def __packetHandler(self, hdr, data):
		""" Use the ImpactDecoder to turn the rawpacket into a hierarchy
		    of ImpactPacket instances.
		    Then search for URLs in packet by regex and log them to list. """
		if self.quit: raise SystemExit('capture on interface stoped.')

		decoded_data = self.decoder.decode(data)
		(src, dst, data) = self.__getHeaderInfo(decoded_data)
		for item in regex_links.finditer(str(data)):
			if not item: continue
			#pos = item.start()
			link = item.groups()[0]
			#self.buffer.append( (link,) )
			self.buffer.append( (link,src,dst,) )	# append to internal buffer

	# thanks to http://d.hatena.ne.jp/shoe16i/mobile?date=20090203&section=p1
	def __getHeaderInfo(self, decoded_data):
		""" Extract the header info completely. """
		ip = decoded_data.child()
		tcp = ip.child()
		#src = (ip.get_ip_src(), tcp.get_th_sport())
		try:	src = ip.get_ip_src()
		except:	src = '?'
		#dst = (ip.get_ip_dst(), tcp.get_th_dport())
		try:	dst = ip.get_ip_dst()
		except:	dst = '?'
		#data = tcp.get_data_as_string()
		data = tcp.get_packet()
		return (src, dst, data)


# MainWindow
# The GUI was created/designed using GLADE
#
class MainWindowGTK:
	"""
	Main GUI class providing cross-platform GTK+ frontend.
	"""

	# initialization
	#
	sniffer = None			# SnifferThread class
	capture_trigger = False		# capture URL?
	capture_index   = 0		# capture index
	capture_last    = None		# capture last entry
	settings 	= { "del_dups": False, "min_icon": False }

	__update_timer = None

	def __init__(self, saved_settings={}):
		""" Initialize and setup GTK+ window and widgets (with help from glade). """
		self.settings.update( saved_settings )		# overwrite default settings with users config

		# retrieve widgets
		self.gladefile		= raw_path + ".glade"
		self.xml		= gtk.glade.XML(self.gladefile)
		self.window1		= self.xml.get_widget('window1')
		self.combobox1		= self.xml.get_widget('combobox1')
		self.combobox2		= self.xml.get_widget('combobox2')
		self.togglebutton1	= self.xml.get_widget('togglebutton1')
		self.button1		= self.xml.get_widget('button1')
		self.scrolledwindow1	= self.xml.get_widget('scrolledwindow1')
		self.treeview1		= self.xml.get_widget('treeview1')
		self.statusbar1		= self.xml.get_widget('statusbar1')
		self.filechooserdialog1	= self.xml.get_widget('filechooserdialog1')
		self.menu1		= self.xml.get_widget('menu1')
		self.aboutdialog1       = self.xml.get_widget('aboutdialog1')
		self.window2		= self.xml.get_widget('window2')
		self.window2.treeview2	= self.xml.get_widget('treeview2')

		# init treeview
		self.__treeview_init()

		# init comboboxes
		self.devs = findalldevs()
		(self.dev_dict, default_dev) = self.getdevips(self.devs)

		self.combobox1.get_model().clear()
		for i, item in enumerate(self.devs):
			self.combobox1.append_text ( item )
			if (item == default_dev): self.combobox1.set_active(i)
		self.combobox2.get_model().clear()
		for item in sorted(dict_filter.keys()):#,reverse=True):
			self.combobox2.append_text ( item )
		self.combobox2.set_active(0)

		# init window2 (options/settings dialog)
		self.__window2_init()

		# init status icon for minimize/iconify to panel/tray
		# thanks to: http://www.pygtk.org/docs/pygtk/class-gtkstatusicon.html
		# and: http://www.mail-archive.com/tracker-list@gnome.org/msg00669.html
		# http://bytes.com/topic/python/answers/580047-pygtk-statusicon-tray-icon
		self.stateico = gtk.StatusIcon()
		self.stateico.set_visible(False)
		if not (os.name == 'nt'):
			icon_name = self.window1.get_icon_name()			# get (and set) icon from window1
			icon = gtk.icon_theme_get_default().load_icon(icon_name, 48, 0)	#
			self.stateico.set_from_pixbuf(icon)
		else:
			self.stateico.set_from_stock(gtk.STOCK_MISSING_IMAGE)
		self.stateico.set_tooltip('PyURLSnooper')

		# connect signal handlers
		# (so late since we don't want to have effects during init of comboxes, etc...)
		self.xml.signal_autoconnect( self )
		self.window1.drag_dest_set(	gtk.DEST_DEFAULT_MOTION |
						gtk.DEST_DEFAULT_HIGHLIGHT |
						gtk.DEST_DEFAULT_DROP,
						[ ( "text/plain", 0, 80 ) ], gtk.gdk.ACTION_COPY)
		self.stateico.connect("activate", self.on_stateico_clicked)

		# display window
		self.window1.show()

		return

	# thanks to http://bugs.python.org/issue6073
	# and http://www.daa.com.au/pipermail/pygtk/2005-October/011297.html
	# and http://www.pardon-sleeuwaegen.be/antoon/python/page0.html
	# (for VERY IMPORTANT GTK+ AND MULT-THREADING HINTS!)
	def run(self):
		""" Run gtk mainloop and with it THIS APP. """
		gtk.gdk.threads_init()			# (!) important for multi-threading to work with GTK+
		self.__update_timer = gobject.timeout_add(250, self.__update, self)
		self.statusbar1.push(0, "Ready (for about dialog; right-click to lower right corner).")
		gtk.main()

	def __update(self, data=None):
		""" Refresh callback to keep the GUI in sync with background thread. """
		if self.sniffer and self.sniffer.buffer:
			buffer = self.sniffer.buffer	# retrieve buffer and ...
			self.sniffer.buffer = []	# ... reset it (maybe a lock would be good?!)
			if self.capture_trigger:
				self.__treeview_append( buffer )
		return True				# keep running continous

	# signals / glade callbacks
	#	
	def on_button1_clicked(self, source=None, event=None):
		""" Button: 'clear'. """
		#self.treeview1.get_model().clear()
		self.model1.clear()
		self.capture_last = None		# reset last entry capture
		self.statusbar1.push(0, "List cleared.")

	# thanks to http://www.pygtk.org/pygtk2tutorial/sec-ToggleButtons.html#togglefig
	def on_togglebutton1_toggled(self, widget, data=None):
		""" Button: 'capture!'. """
		if (widget.get_active() == 1):							# capture ON
			self.combobox1.set_sensitive(False)					# lock combobox
			#dev = self.combobox1.get_child().get_text()
			dev = self.combobox1.get_model()[self.combobox1.get_active()][0]
			(self.dev_dict, default_dev) = self.getdevips(self.devs)		# refresh dict
			p = open_live(dev, 1500, 0, 100)					# open interface for catpuring
			#p.setfilter(filter)							# set the BPF filter, see tcpdump(3)
			p.setfilter('')								#
			self.sniffer = SnifferThread(p)						# Create sniffing thread and ...
			self.sniffer.start()							# ... start it

			self.capture_trigger = True
			widget.set_label("stop")
			self.statusbar1.push(0, "Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink()))
		else:										# capture OFF
			#self.sniffer.pcap.close()
			self.sniffer.quit = True
			del self.sniffer
			self.sniffer = None

			self.capture_trigger = False
			widget.set_label("capture!")
			self.combobox1.set_sensitive(True)					# unlock combobox (again)
			self.statusbar1.push(0, "Capture stopped.")

	def on_window1_destroy(self, source=None, event=None):
		""" Window closed signal handler. """
		self.statusbar1.push(0, "Quit.")
		if self.sniffer:
			self.sniffer.quit = True
			del self.sniffer
			self.sniffer = None
		gobject.source_remove(self.__update_timer)
		gtk.main_quit()

	# thanks to http://www.pygtk.org/docs/pygtk/class-pygtktreemodelrow.html
	# and http://www.pygtk.org/docs/pygtk/class-gtktreemodel.html
	# thanks to http://www.pygtk.org/pygtk2tutorial/sec-FileChoosers.html
	def on_button2_clicked(self, source=None, event=None):
		""" Button: 'save...'. """
		# open save file dialog
		response = self.filechooserdialog1.run()
		if response == gtk.RESPONSE_OK:
			filename = self.filechooserdialog1.get_filename()

			# write file
			outfile = open(filename, "w")
			for item in iter(self.treeview1.get_model()):
				outfile.write( ",".join(map(str, item[0])) )
				outfile.write( '\n' )
			outfile.close()
			self.statusbar1.push(0, "List saved.")
		self.filechooserdialog1.hide()				# just hide - not destroy - preserves settings

	# thanks to http://faq.pygtk.org/index.py?req=show&file=faq13.017.htp
	def on_treeview1_button_press_event(self, treeview, event):
		""" Treeview mouse right-click signal handler. """
		if event.button == 3:
			x, y = int(event.x), int(event.y)
			time = event.time
			pthinfo = treeview.get_path_at_pos(x, y)
			if pthinfo is not None:
				path, col, cellx, celly = pthinfo
				treeview.grab_focus()
				treeview.set_cursor( path, col, 0)
				self.menu1.popup( None, None, None, event.button, time)
			return True

	# thanks to http://www.answermysearches.com/python-how-to-copy-and-paste-to-the-clipboard-in-linux/286/
	# and http://www.mail-archive.com/pygtk@daa.com.au/msg06091.html
	def on_item1_activate(self, treeview):
		""" Popupmenu: 'copy...'. """
		(path, column) = self.treeview1.get_cursor()
		row = path[0]
		#col = self.treeview1.get_columns().index(column)
		col = self.column_header.index(column.get_title())				# respect re-ordered columns
		#text = str( self.treeview1.get_model()[row][0][col] )				# Copy only the selected cell/column
		text = str( self.treeview1.get_model()[row][col+self.hidden_data_prepend] )	#
		# get the clipboard
		clipboard = gtk.clipboard_get()
		# set the clipboard text data
		clipboard.set_text(text)
		# make our data available to other applications
		clipboard.store()
		self.statusbar1.push(0, "Copied to clipboard.")

	# thanks to http://www.pygtk.org/pygtk2tutorial/sec-TreeViewDragAndDrop.html
	# and http://www.pygtk.org/pygtk2tutorial/sec-DNDMethods.html
	#def on_treeview1_drag_data_received(self, treeview, context, x, y, selection, info, timestamp):
	def on_window1_drag_data_received(self, treeview, context, x, y, selection, info, timestamp):
		""" Drag'n'Drog signal handler. """
		data = selection.data
		for i, item in enumerate(self.treeview1.get_model()):
			if (data in str(item[0])):
				self.treeview1.set_cursor( (i,) )
				self.statusbar1.push(0, "Entry found and selected.")
				return
		self.statusbar1.push(0, "Nothing found.")

	# thanks to http://zetcode.com/tutorials/pygtktutorial/signals/
	def on_window1_configure_event(self, source=None, event=None):
		""" Window resized signal handler. """
		self.scrolledwindow1.set_property('width-request',  event.width  - self.size_offset[0])
		self.scrolledwindow1.set_property('height-request', event.height - self.size_offset[1])
		#self.window1.do_configure_event(source, event)

	def on_combobox2_changed(self, source=None, event=None):
		""" Combobox changed signal handler. """
		pattern = dict_filter[self.combobox2.get_model()[self.combobox2.get_active()][0]]
		if not pattern:	self.treeview1.set_model(self.model1)		# switch used model since one supports sorting only
		else:		self.treeview1.set_model(self.modelfilter1)	# and the other filtering only - none of them both
		self.treeview1.set_search_column(self.search_colid)		# re-enable searching in 'URL' column
		self.modelfilter1.refilter()					# apply filter conditions
		self.statusbar1.push(0, "Other filter selected.")

	def on_columnext_toggled(self, cell, path):
		""" Sets the toggled state on the toggle button to true or false. """
		path = self.treeview1.get_model()[path][0][0]			# get correct path where checkbox was toggled (bugfix if using filter)
		self.model1[path][3] = not self.model1[path][3]			# toggle cell (finally)
		#print "Toggle '%s' to: %s" % (self.model1[path][0], self.model1[path][3],)
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		# Echo client program
		try:								# Try to connect to the socket and ...
			s.connect(('localhost', 50301))					# (The remote host, The same port as used by the server)
			s.send(str( (self.model1[path][0], self.model1[path][3],) ))	# send data
		except:								# ...  turn exception into warning
			warnings.warn("Could not connect to socket. Is any client program running?", Warning)
		#data = s.recv(1024)						# (recieve data)
		s.close()							# close socket
		#print 'Received', repr(data)					#

	# thanks to: http://zetcode.com/tutorials/pygtktutorial/dialogs/
	# thanks to: http://www.pygtk.org/docs/pygtk/class-gtkwindow.html
	# and http://www.pygtk.org/docs/pygtk/class-gtkicontheme.html
	def on_statusbar1_button_press_event(self, *data):
		""" Statusbar button press signal handler. """
		widget, event = data
		if (event.button == 3):		# show about on right-click
			self.aboutdialog1.set_version( __version__.split(",")[1][2:5] )	# set actual
			if not (os.name == 'nt'):
				self.aboutdialog1.set_program_name( "PyURLSnooper" )		# (is overwritten?!?)
				#about.set_logo(gtk.gdk.pixbuf_new_from_file("battery.png"))
				icon_name = self.window1.get_icon_name()			# get (and set) icon from window1
				icon = gtk.icon_theme_get_default().load_icon(icon_name, 48, 0)	#
				self.aboutdialog1.set_logo( icon )				#
			self.aboutdialog1.run()
			self.aboutdialog1.hide()

	# thanks to http://bbs.archlinux.org/viewtopic.php?pid=705541
	# and http://library.gnome.org/devel/pygtk/stable/class-gtktreeviewcolumn.html#method-gtktreeviewcolumn--set-cell-data-func
	def on_celldatamethod(self, column, cell, model, iter, user_data=None):
		""" Sets the visible state/visibility for all renderer types. """
		# should be a short/fast function since it is called very often!
		#datatype = model[iter][0]["type"]
		cell.set_property('visible', (user_data[0]==model[iter][0]["type"]))
		if (user_data[0]=="check"):
			cell.set_radio(model[iter][0].get("radio", False))
		#self.window2.m.clear()
		#for item in model[iter][0].get("combo", []):
		#	self.window2.m.append([item])

	def on_columnvalue_modified( self, *data ):
		""" Sets the new value after edit for all renderer types. """
		if (len(data) == 4):	( cell, path, model, user_data ) = data
		else:			( cell, path, new_text, model, user_data ) = data
		(datatype,) = user_data
		colid = self.window2.type2colid[datatype]
		if 	(datatype == "combo"):
			model[path][colid] = new_text
		elif 	(datatype == "spin"):
			model[path][colid] = long(new_text)
		elif 	(datatype == "text"):
			model[path][colid] = new_text
		elif 	(datatype == "check"):
			model[path][colid] = not model[path][colid]

	# thanks to: http://www.pygtk.org/articles/applets_arturogf/x134.html
	def on_window2_delete_event(self, *data):
		""" Window (window2: options/settings dialog) closed signal handler. 
		    (performs also all clean-up actions)."""
		self.window2.hide()
		result = []
		for item in iter(self.window2.mdl):
			for subitem in item.iterchildren():
				entry = [ subitem[i] for i in range(6) ]
				colid = self.window2.type2colid[entry[0]["type"]]
				result.append( entry[colid] )
		self.settings = { "del_dups": result[0], "min_icon": result[1] }
		self.statusbar1.push(0, "New options/settings applied.")
		return True

	def on_button5_clicked(self, source=None, event=None):
		""" Button: 'config...'. """
		self.window2.settings =  [ 	( "result display", {"remove (direct) duplicates":("check", self.settings["del_dups"])} ),
						( "window behaviour", {"iconify/minimize to panel/tray":("check", self.settings["min_icon"])} ),
						#( "TESTING1", {"test11":("combo", ["a", "b"], 2), "test12":("spin", 7), "test13":("text", "xyz")} ),
						#( "TESTING2", {"test21":("radio", False), "test22":("radio", False), "test23":("radio", False)} ),
						]

		self.window2.mdl.clear()
		# places the global people data into the list
		# we form a simple tree.
		for item in self.window2.settings:
			parent = self.window2.mdl.append( None, ({"type":"head"}, item[0], "combo", 0, "text", False) )
			for subitem in item[1]:
				entry = item[1][subitem]
				txt   = str(entry[1])
				try:	num = long(entry[1])
				except:	num = 0
				hiddendata = {"type":entry[0]}
				#if (entry[0]=="combo"): hiddendata["combo"] = entry[1]
				if (entry[0]=="radio"): hiddendata.update({"type":"check","radio":True})
				self.window2.mdl.append( parent, (hiddendata, subitem, txt, num, txt, bool(entry[1])) )

		self.window2.treeview2.expand_all()
		self.window2.show()

	# thanks to: http://www.pygtk.org/docs/pygtk/class-gtkwindow.html#method-gtkwindow--iconify
	# and: http://www.pygtk.org/docs/pygtk/class-gdkevent.html
	# http://www.codeproject.com/KB/cross-platform/GTKTrayIcon.aspx
	def on_window1_window_state_event(self, widget, event, *user_params):
		""" Window state changed (e.g. minimized/iconified) signal handler. """
		if not self.settings["min_icon"]: return
		if (event.changed_mask == gtk.gdk.WINDOW_STATE_ICONIFIED):							# minimize button clicked
			if ( (event.new_window_state == gtk.gdk.WINDOW_STATE_ICONIFIED) or
			     (event.new_window_state == gtk.gdk.WINDOW_STATE_ICONIFIED | gtk.gdk.WINDOW_STATE_MAXIMIZED) ):	# going to iconify
				#self.window1.iconify()			# for smooth change with compiz
				#while gtk.events_pending():
				#	gtk.main_iteration()
				self.stateico.set_visible(True)
				self.window1.set_property('visible', False)

	def on_stateico_clicked(self, *a):
		""" StatusIcon clicked signal handler. """
		self.window1.set_property('visible', True)
		self.stateico.set_visible(False)
		self.window1.present()

	# helpers
	#	
	# thanks to http://coding.debuntu.org/python-gtk-treeview-rows-different-colors
	# http://www.pygtk.org/docs/pygtk/class-gtktreeviewcolumn.html#method-gtktreeviewcolumn--set-sort-column-id
	def __treeview_init(self):
		""" Initialize and build treeview widget underlining structure with all its funcionality. """
		# create list data storage element (1st model; supports sorting)
		self.hidden_data_prepend = 4				# first ? items are hidden internal data
		self.model1 = gtk.ListStore( gobject.TYPE_PYOBJECT,	# data: whole data tuple (hidden)	id 0
					     str,			# color: which one	 (hidden)	id 1
					     bool,			# color: off/on?	 (hidden)	id 2
					     gobject.TYPE_BOOLEAN,	# ext: off/on?	 	 (hidden)	id 3
		                             gobject.TYPE_LONG,		# column: Index				id 4 (hidden_data_prepend)
		                             gobject.TYPE_STRING,	# column: URL				id 5
		                             gobject.TYPE_STRING,	# column: Protocol			id 6
		                             gobject.TYPE_STRING)	# column: Adapter			id 7
		self.treeview1.set_model(self.model1)
		# create filtered model element (2nd model; supports filtering, but not sorting)
		self.modelfilter1 = self.model1.filter_new()
		self.modelfilter1.set_visible_func(self.__url_filter, data=None)
		# create cell renderer element for use in columns (see next block)
		self.renderer1 = gtk.CellRendererText()
		# create column elements according to given header and hidden elements (indices order has to match with model1 ids!)
		self.column_header = [ "Index", "URL", "Protocol", "Adapter" ]
		column = []
		for col in range(len(self.column_header)):
			colid = col + self.hidden_data_prepend		# skip hidden items at beginning in id counting
			colpreset = gtk.TreeViewColumn(self.column_header[col], self.renderer1, text=colid, foreground=1, foreground_set=2)
			colpreset.set_resizable(True)			# enable column width resizing
			colpreset.set_reorderable(True)			# enable column re-ordering
			colpreset.set_sort_column_id(colid)		# enable column sorting (sets also 'set_headers_clickable' and others)
			column.append( colpreset )			# set defined column
		if ext_sup:								# set additional column depending
			colid = self.hidden_data_prepend - 1				#   on 'ext' support on/off?
			rend = gtk.CellRendererToggle()					#   (everything like before)
			rend.set_property('activatable', True)				#
			rend.connect('toggled', self.on_columnext_toggled)		#
			colpreset = gtk.TreeViewColumn("ext", rend, active=colid)	#
			colpreset.set_resizable(True)					#
			colpreset.set_sort_column_id(colid)				#
			column.append( colpreset )					#
		for col in column:					# append setted columns
			self.treeview1.append_column(col)		#
		# final treeview adjustments
		self.search_colid = self.hidden_data_prepend + 1	# enable searching in 'URL' column (+1 since 2nd visible)
		self.treeview1.set_search_column(self.search_colid)	#
		#self.treeview1.enable_model_drag_dest([('text/plain', 0, 0)], gtk.gdk.ACTION_DEFAULT | gtk.gdk.ACTION_MOVE)
		self.treeview1.set_reorderable(True)			# enable row re-ordering
		# size offset calculation
		width  = self.window1.get_property('width-request') - self.scrolledwindow1.get_property('width-request')
		height = self.window1.get_property('height-request') - self.scrolledwindow1.get_property('height-request')
		self.size_offset = (width, height)

	def __treeview_append(self, newbuffer):
		""" Append row to treeview from extracted sniffer data buffer. """
		new_iter = None
		for data in newbuffer:
			dev = self.dev_dict.get(data[1], self.dev_dict.get(data[2], "?"))	# try to get device/adapter
			url = data[0].replace('\\','')						# remove Backslashes from link/url (filter 1)
			urlinfo = urlparse.urlparse(url)					# get protocol
			proto, port = urlinfo.scheme, urlinfo.port				# 
			data = (self.capture_index, url, proto, dev)				# create enhanced data
			self.capture_index += 1							# increase capture index
			dup = (self.capture_last == data[1:])					# is this a duplicate of last entry?
			self.capture_last = data[1:]						# store this entry for next duplicate check
			if self.settings["del_dups"] and dup: continue				# if option set; skip adding of duplicates
			new_iter = self.model1.append( (data,'#888888',dup,False,) + data[0:] )	# add data (hidden + columns) as new row

	# thanks to http://www.pygtk.org/pygtk2tutorial/sec-CellRenderers.html
	# and http://www.pygtk.org/pygtk2reference/
	# and http://www.pygtk.org/pygtk2tutorial/examples/treeviewcolumn.py
	# and http://www.daa.com.au/pipermail/pygtk/2004-December/009359.html
	# and http://ubuntuforums.org/showthread.php?t=292791
	def __window2_init(self, *a):
		""" Initialize and build window and treeview widget underlining structure with all its funcionality. """
		self.window2.type2colid = { "combo":2, "spin":3, "text":4, "check":5 }	# see below
		# Get the model and attach it to the view
		self.window2.mdl = gtk.TreeStore(	gobject.TYPE_PYOBJECT,		# id 0: (hidden data)
				            		gobject.TYPE_STRING, 		# id 1: column 1 option label/name
				            		gobject.TYPE_STRING, 		# id 2: column 2 combo
							gobject.TYPE_LONG,		# id 3: column 2 spin
				            		gobject.TYPE_STRING, 		# id 4: column 2 text
				            		gobject.TYPE_BOOLEAN ) 		# id 5: column 2 check/toggle
		self.window2.treeview2.set_model(self.window2.mdl)

		# list store and adjustment for cell renderers
		self.window2.m = gtk.ListStore(gobject.TYPE_STRING)
		#self.window2.m.append(["(empty)"])
		adjust = gtk.Adjustment(0, 0, 100, 1)

		# setup the text cell renderer
		# The text/label cellrenderer is setup (non-changeable by the user).
		# Connect column0 of the display with column 0 in our list model
		self.window2.renderer1 = gtk.CellRendererText()							# column 1 renderer
		self.window2.column0 = gtk.TreeViewColumn("Setting", self.window2.renderer1, text=1)		# column 1
		# Setup the data cell with 4 renderers and allows these
		# renderers to be edited. In order to do this we have to
		# setup the columns first.
		self.window2.column1 = gtk.TreeViewColumn("Value" )						# column 2
		self.window2.renderer2_1 = gtk.CellRendererCombo()						# column 2 renderer 1: ComboBoxEntry
		#self.window2.renderer2_1.set_properties(editable=True, model=self.window2.m, text_column=0)	#
		self.window2.renderer2_1.set_property('editable',True)						#
		self.window2.renderer2_1.set_property('model',self.window2.m)					#
		self.window2.renderer2_1.set_property('text_column',0)						#
		if not (os.name == 'nt'):	# not for PyGTK <= 2.14 (http://www.python-forum.de/viewtopic.php?p=138475&sid=594b72d32face545ac08801f9f10b3ba)
			self.window2.renderer2_1.connect('changed', self.on_columnvalue_modified, self.window2.mdl, ("combo",) )#
		self.window2.renderer2_1.connect('edited',  self.on_columnvalue_modified, self.window2.mdl, ("combo",) )	#
		self.window2.column1.pack_start(self.window2.renderer2_1, True)					#
		self.window2.renderer2_2 = gtk.CellRendererSpin()						# column 2 renderer 2: SpinEntry
		#self.window2.renderer2_2.set_properties(adjustment=adjust, editable=True)			#
		self.window2.renderer2_2.set_property('adjustment',adjust)					#
		self.window2.renderer2_2.set_property('editable',True)						#
		self.window2.renderer2_2.connect('edited',  self.on_columnvalue_modified, self.window2.mdl, ("spin",) )		#
		self.window2.column1.pack_start(self.window2.renderer2_2, True)					#
		self.window2.renderer2_3 = gtk.CellRendererText()						# column 2 renderer 3: TextEntry
		self.window2.renderer2_3.set_property('editable', True)						#
		self.window2.renderer2_3.connect('edited',  self.on_columnvalue_modified, self.window2.mdl, ("text",) )		#
		self.window2.column1.pack_start(self.window2.renderer2_3, True)					#
		self.window2.renderer2_4 = gtk.CellRendererToggle()						# column 2 renderer 4: CheckBox/ToggleButton
		self.window2.renderer2_4.set_property('activatable', True)					#
		self.window2.renderer2_4.connect('toggled', self.on_columnvalue_modified, self.window2.mdl, ("check",) )	#
		self.window2.column1.pack_start(self.window2.renderer2_4, False)				#
		# The columns state/data is attached to the columns in the model.
		self.window2.column1.set_attributes(self.window2.renderer2_1, text=2)
		self.window2.column1.set_attributes(self.window2.renderer2_2, text=3)
		self.window2.column1.set_attributes(self.window2.renderer2_3, text=4)
		self.window2.column1.add_attribute( self.window2.renderer2_4, "active", 5)
		# Handle the visiblility of the different renderer per cell.
		self.window2.column1.set_cell_data_func(self.window2.renderer2_1, self.on_celldatamethod, ("combo",))
		self.window2.column1.set_cell_data_func(self.window2.renderer2_2, self.on_celldatamethod, ("spin",))
		self.window2.column1.set_cell_data_func(self.window2.renderer2_3, self.on_celldatamethod, ("text",))
		self.window2.column1.set_cell_data_func(self.window2.renderer2_4, self.on_celldatamethod, ("check",))
		self.window2.treeview2.append_column( self.window2.column0 )
		self.window2.treeview2.append_column( self.window2.column1 )

	# thanks to http://www.pygtk.org/pygtk2tutorial/sec-TreeModelSortAndTreeModelFilter.html#sec-TreeModelFilter
	# and http://www.pygtk.org/pygtk2tutorial/examples/treemodelfilter.py
	def __url_filter(self, model, iter, user_data):
		""" Filter URL (and whole tuple) for special string. """
		pattern = dict_filter[self.combobox2.get_model()[self.combobox2.get_active()][0]]
		return pattern in str(model.get_value(iter, 0))

	# thanks to: http://code.activestate.com/recipes/439094/
	# thanks to: http://timgolden.me.uk/python/wmi/cookbook.html#examples
	# and http://libdnet.sourceforge.net/pydoc/ (both for windows)
	def getdevips(self, devs):
		""" Resolve IPs assigned to given network devices and create translation dict. """
		print "Try to detect network interface names and default adapter:"
		result = {}
		if   (os.name == 'posix') or (os.name == 'mac'):
			default = 'any'
			for dev in devs:
				try:
					s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					ip = socket.inet_ntoa(fcntl.ioctl(
						s.fileno(),
						0x8915,  # SIOCGIFADDR
						struct.pack('256s', dev[:15])
					)[20:24])
					print dev, ip
					result[ip] = dev
					if (default == 'any'): default = dev
				except IOError:
					pass
		elif (os.name == 'nt') and ("wmi" in imported):
			default = None
			dev_names = {}
			if ("dnet" in imported):
				def store_cb(*data): dnet_devs.append( data )
				dnet_devs = []
				dnet.intf().loop(store_cb)
				#dnet.intf().loop(dnet_devs.append)
				for dev in dnet_devs:
					if "addr" not in dev[0]: continue
					dev_names[str(dev[0]["addr"]).rsplit("/")[0]] = dev[0]["name"]
			for interface in wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=1):
				#print interface
				dev = "\\Device\\NPF_" + interface.SettingID
				(ip, info) = interface.IPAddress
				desc, mac = interface.Description, interface.MACAddress
				print dev, ip, dev_names.get(ip, ''), "\n(", desc, ")"
				result[ip] = dev
				if not default: default = dev
		else:	# 'nt' (WITHOUT wmi), 'os2', 'ce', 'java', 'riscos'
			default = None
			print "(none)"

		return (result, default)


# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# Functions
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
#
# thanks to http://stackoverflow.com/questions/858916/how-to-redirect-python-warnings-to-a-custom-stream
# and http://docs.python.org/library/warnings.html
# (of course there is always the sys.stdout, stderr way, but we want warnings only!)
def customwarn(message, category, filename, lineno, file=None, line=None):
	log.write(warnings.formatwarning(message, category, filename, lineno)+'\n')
	log.flush()



# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# Main
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
#
if __name__ == '__main__':
	# check permissions
	try:
		ifs = findalldevs()
		# No interfaces available, abort.
		if 0 == len(ifs):
			raise pcapy.PcapError
	except pcapy.PcapError:
		print "You have not the permissions needed, you should be root/admin."
		sys.exit(1)

	# redirect warnings to log
	log = open(raw_path + ".log", 'w')
	warnings.showwarning = customwarn
	#warnings.simplefilter('error')		# debug/devel setting
	#warnings.simplefilter('once')		# default setting (?)
	warnings.simplefilter('always')		# (since we are in beta phase; a little bit more verbosity)

	## Process command-line arguments. Take everything as a BPF filter to pass
	## onto pcap. Default to the empty filter (match all).
	#filter = ''
	#if len(sys.argv) > 1:
	#    filter = ' '.join(sys.argv[1:])

	# get saved options/settings from config file
	try:
		cfg = open(raw_path + ".cfg", 'r')
		data = cfg.read()
		cfg.close()
		saved_settings = eval(data)
	except:
		saved_settings 	= {}

	# run main application
	main = MainWindowGTK(saved_settings)
	main.run()

	# store options/settings to config file
	cfg = open(raw_path + ".cfg", 'w')
	cfg.write( str(main.settings) )
	cfg.close()

	log.close()
	sys.exit()

