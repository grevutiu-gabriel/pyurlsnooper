""" === Default Library/Module for Python by Dr. Trigon ===
"""

__version__ = "beta"

## Documentation for this module.
#
# \brief Brief description.
#        Brief description continued.
# More details.

import sys, inspect
import StringIO, traceback
import threading, gtk


class MultClass():
	"""Multiplicate a command sequence, to send it to more than one
	class at once.

	Example of the mechanics for multiplication of stream output to
        two files:
	   file1, file2 = open(...), ...
	   dup = MultClass(file1, file2)
	   dup.write("x")
	   ...
	dup.write will trigger __getattr__ and store the function
	name "write" internaly to __func. It will also return an 
	object (in fact the class itself which is callable) so that
	[class]("x") will be evaluated and trigger the __call__ method
	which calls both file streams in order.
	"""

	__func = ""

	def __init__(self, *classlist):
		"""The constructor for the class.

		classlist   give any number >= 1 of classes to use"""

		#self.class1, self.class2 = c1, c2
		self.__classes = list(classlist)

	def __getattr__(self, name):
		"""Method/Function will be called for nearly everything. It
                emulates together with __call__ every call to any class
                method and feed they through to class1 and class2.

		name     name of the method (or else), stored for call"""

		self.__func = name
		return self

	def __call__(self, *vlist, **vdict):
		"""Method/Function will be normally called right after the
		__getattr__ method. It emulates together with __getattr__
		every call to any class method and feed they through to
		class1 and class2.

		*vlist   takes all 'normal' arguments as list
		**vdict  takes all 'dict-args'?! as dict"""

		#params = list(vlist)
		# ...and vdict ?!
		##apply(self.stream1.__dict__[self.__func], params1)
		#if not (self.class1 == None): apply(getattr(self.class1, self.__func), params)
		for clss in self.__classes: apply(getattr(clss, self.__func), vlist)
		self.__func = ""

	def __get_classes(self): return self.__classes
	def __set_classes(self, *classlist):
		self.__classes = list(classlist)
		#setattr(self.__class, self.__stream, self.__repl)
	## Multiplication classes.
	classes = property(__get_classes, __set_classes, doc = "List of used classes.")


# from 'PyETHVPP_v16.py'
# ATTENION: Only calling once is allowed for 'del' or else you will
# kill the python interpreter for current session.
# This class is very similar to DupClass in it's behaviour, with
# the small difference that this class also sets the new streams
# up and restores the old ones after deletion/release.
#
# http://www.electricmonk.nl/log/2008/07/07/python-destructor-and-garbage-collection-notes/
# http://docs.python.org/library/gc.html
# http://docs.python.org/reference/datamodel.html
class RedirStream(object):
	"""Redirect specific standard stream to self defined stream.
	(child of object to be able to use property function)

	Example of the mechanics for stream switch with file output:
	   file1 = file(...)
	   sys.stdout = RedirStream( file1 )
	   print ...
	   ...
	   del sys.stdout	# must not called more than once!
	   file1.close()
	RedirStream sets a set of streams as standard stream (by default
	is the original stream added to this list). When the 
	RedirStream-Object gets deleted it restores the original
	stream configuration. The module is strict in the calling command
	lines accepted, since it has to figure out, which stream was set.
	In default mode (secure = True) the class keeps itself living, so
	if you accidentially 'del' once again, the python interpreter will
	be preserved from crashing.
	"""

	__func = ""
	__error = False

	def __init__(self, *streamlist, **kwarg):
		"""The constructor for the class. Creates a RedirStream-Object.

		streamlist   give any number >= 1 of streams to use
		stdstream    use the original stream too (default)
		secure       use secure mode and prevent 'del' from doing nasty things
		"""
		stdstream     = kwarg.get('stdstream', True)
		self.__secure = kwarg.get('secure', True)

		# figure out which stream to change
		try:	self.__bind = eval(str(inspect.getouterframes(inspect.currentframe())[-1][4][-1]).split("=")[0]).name[1:-1]
		except:	self.__bind = None
		if not self.__bind:
			self.__error = True
			raise SyntaxError, "only something like 'sys.std... = RedirStream(stream1, ...)' is alowed"

		# set streams
		# in fact it would be better NOT to store the 'sys.__std...__' localy, because of 'self.__del__'
		# (look also next comment), but it seams to work, is faster and less CPU consuming
		if stdstream:	self.__streams = [getattr(sys, '__%s__'%self.__bind)]
		else:		self.__streams = []
		self.__streams += list(streamlist)
		# if you want to use other streams than 'sys' too; save the original in
		# 'globals()' or other external dict instead of 'self' (like 'sys.__stdout__')
		# to prevent circular references that excludes 'self.__del__' from execution
		sys.__stdout__.write("%s stream redirected to targets: %s\n" % (self.__bind, self.__streams))

	def __del__(self):
		"""The destructor for the class. Restores the original setting."""

		if self.__error: return

		# restore original setting
		if self.__secure:		# in secure mode, keep class, but only one stream (protect from 'del')
			try:	self.__streams = [getattr(sys, '__%s__'%self.__bind)]
			except:	return		# real, final python exit
			new = self
		else:
			new = getattr(sys, '__%s__'%self.__bind)
		setattr(sys, self.__bind, new)
		sys.__stdout__.write("%s original stream restored (secure: %s)\n" % (self.__bind, self.__secure))

	def __getattr__(self, name, *vlist, **vdict):
		self.__func = name
		return self

	def __call__(self, *vlist, **vdict):
		# http://diveintopython.org/scripts_and_streams/stdin_stdout_stderr.html
		if self.__error:	streams = [ sys.__stderr__ ]
		else:			streams = self.__streams
		for stream in streams: apply(getattr(stream, self.__func), vlist)
		self.__func = ""

	def __get_streams(self): return self.__streams
	#def __set_streams(self, *streamlist):
	#	pass
	#	#setattr(self.__class, self.__stream, self.__repl)
	## Replacement streams. READ-ONLY
	#streams = property(__get_streams, __set_streams)
	streams = property(__get_streams, doc = "List of used streams.")


#class SuperStream(object):
#	"""A SuperStream object takes control over the two standard output
#	stream stdout and stderr. It provides you a big set of new options.
#	(child of object to be able to use property function)
#	"""
#
#	__usestd = True
#	__usefile = False
#
#	def __init__(self, logfilename = ""):
#		"""The constructor for the class. Creates a SuperStream-Object.
#
#		logfilename  is the name of the log file stream to use, see usestd
#		"""
#
#		# c1 = self.__logfile (if existing), c2 = sys....
#		self.__change_out = SwitchStreams( (sys, "stdout"), DupClass(c2 = sys.stdout) )
#		self.__change_err = SwitchStreams( (sys, "stderr"), DupClass(c2 = sys.stderr) )
#
#		if (logfilename <> ""): self.__set_logfilename(logfilename)
#
#	def __del__(self):
#		"""The destructor for the class. Deletes the SuperStream-Object
#		and restores the original setting."""
#
#		# close file
#		self.__del_logfilename()
#
#		# delete SwitchStream-Objects: reset the original streams
#		del self.__change_out, self.__change_err
#
#	def __get_usestd(self): return self.__usestd
#	def __set_usestd(self, x):
#		self.__usestd = bool(x)
#		if self.__usestd:
#			self.__change_out.repl.class2 = self.__change_out.orig
#			self.__change_err.repl.class2 = self.__change_err.orig
#		else:
#			self.__change_out.repl.class2 = None
#			self.__change_err.repl.class2 = None
#	## Use standard outputs.
#        usestd = property(__get_usestd, __set_usestd, doc = "Use standard outputs.")
#
#	def __get_usefile(self): return self.__usefile
#	def __set_usefile(self, x):
#		self.__usefile = bool(x)
#		if self.__usefile:
#			try:
#				self.__change_out.repl.class1 = self.__logfile
#				self.__change_err.repl.class1 = self.__logfile
#			except:
#				raise ValueError, 'logfile/logfilename not defined'
#		else:
#			self.__change_out.repl.class1 = None
#			self.__change_err.repl.class1 = None
#	## Use log file output.
#        usefile = property(__get_usefile, __set_usefile, doc = "Use log file output.")
#
#	def __get_logfile(self): return self.__logfile
#	def __set_logfile(self, x = None):
#		if (x == None): raise ValueError, 'use del ... instead'
#		self.__logfile = x
#		self.__logfilename = self.__logfile.name
#		self.__set_usefile(self.__usefile)
#	def __del_logfile(self):
#		self.__set_usefile(False)
#		del self.__logfile, self.__logfilename
#	## Log file to use as first output (should be opened in APPEND mode).
#        logfile = property(__get_logfile, __set_logfile, __del_logfile, "Log file to use a first output (should be opened in append mode).")
#
#	def __get_logfilename(self): return self.__logfilename
#	def __set_logfilename(self, x = ""):
#		if (x == ""): raise ValueError, 'use del ... instead'
#		try:
#			self.__logfile.close()
#		except:
#			pass
#		#logfile = file(x, "w")
#		logfile = file(x, "a")
#		self.__set_logfile(logfile)
#	def __del_logfilename(self):
#		try:
#			self.__logfile.close()
#		except:
#			pass
#		self.__del_logfile()
#	## Log file name to use a first output (internal file handling).
#        logfilename = property(__get_logfilename, __set_logfilename, __del_logfilename, "Log file name to use a first output (internal file handling).")


# thanks to http://bugs.python.org/issue6073
# and http://www.daa.com.au/pipermail/pygtk/2005-October/011297.html
# and http://www.pardon-sleeuwaegen.be/antoon/python/page0.html
# (for VERY IMPORTANT GTK+ AND MULT-THREADING HINTS!)
#
# class Thread(PyLib.Thread):
#	def __init__(self):
#		PyLib.Thread.__init__(self, use_gtk=True)	# with use_gtk=True it is gtk thread safe
#	def loop(self):						# use 'loop' instead of 'run' in threading.Threads
#		...						#    it should come back regularly, to enable 'stop'
#		self.callback(...)				# call callback_func on a safe way
#		...
#
# test = Thread()
# test.callback_func = ...	# define any callback_func to use
# ...
# test.start()
# ...
# test.stop()			# default is not to come back until finished
# ...
#
class Thread(threading.Thread):
	# public
	callback_func = None

	# internal private
	__cancel = None

	def __init__(self, use_gtk=False):
		""" ... """
		self.__use_gtk = use_gtk

		if self.__use_gtk: gtk.gdk.threads_init()			# (!) important for multi-threading to work with GTK+
		threading.Thread.__init__(self)

	def run(self):
		""" Run thread. """
		while not self.__cancel: self.loop()				# run 'loop'
		#self.__cancel.set()						# set finish signal

	def callback(self, *a, **b):
		""" Thread callback (GTK safe). """
		if self.__use_gtk: 	gtk.gdk.threads_enter()			# acquire the lock
		if self.callback_func: 	self.callback_func(self, *a, **b)	# do safe callback
		if self.__use_gtk: 	gtk.gdk.threads_leave()			# release it

	def stop(self, wait=True):
		""" Stop thread. """
		self.__cancel = True
		if wait: self.is_alive()					# wait for clean finish
		#self.__cancel = threading.Event()
		#if wait: self.__cancel.wait()					# wait for clean finish


# from 'runbotrun.py'
def tb_info(exc_info=None):
	"""Returns the same information as 'sys.exc_info' in the same format (tuple).
	The difference is that the traceback info (3rd tuple item) is resolved to
	a text representation of the traceback (human readable).

	exc_info   is the exception info, default is 'sys.exc_info'
	"""

	if not exc_info: exc_info = sys.exc_info()	# default

	output = StringIO.StringIO()
	traceback.print_exception(exc_info[0], exc_info[1], exc_info[2], file=output)
	result = output.getvalue().split('\n')
	output.close()
	#exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
	return (exc_info[0], exc_info[1], result)



