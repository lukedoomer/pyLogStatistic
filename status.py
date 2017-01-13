#!/usr/bin/python3

import timeit

class Timer:
	def __init__(self):
		self.start_time = None
		
	def start(self, status):
		print(status)
		self.start_time = timeit.default_timer()

	def stop(self):
		print('\tElapsed time: %.2f seconds' % (timeit.default_timer() - self.start_time))