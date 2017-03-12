% Venkatraman Renganathan
% W_MSR Code tackling the spoofing attack
% Input initial conditions of node values
% See the consensus converging despite having F malicious nodes
clear all; close all; clc;
prompt = 'Specify the number of agents in the network --> ';
m = input(prompt);
prompt = 'Specify the number of malicious agents you want in the network --> ';
F = input(prompt);
prompt = 'Specify the number of agents to be spoofed by the malicious node in the network --> ';
spoof_count = input(prompt);
prompt = 'Specify the time span to reach consensus --> ';
time_span = input(prompt);
prompt = 'Specify the delay (Usually < above time span) within which the spoofed nodes are identified --> ';
delay = input(prompt);
% Create random initial values for vehicles
x_0 = 10*abs(randn(m,1));
x = delayed_spoofing_wmsr(m, F, spoof_count, time_span, delay, x_0);
time_vec = 0:1:time_span;
plot(time_vec,x);
title('Consensus of Information States of Nodes');
xlabel('Time Steps');
ylabel('Information States of Nodes');
a = findobj(gcf, 'type', 'axes');
h = findobj(gcf, 'type', 'line');
set(h, 'linewidth', 5);
set(a, 'linewidth', 4);
set(a, 'FontSize', 24);
