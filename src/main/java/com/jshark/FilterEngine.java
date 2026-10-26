package com.jshark;

import org.pcap4j.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BPF filter engine for packet filtering
 */
public class FilterEngine {
    private static final Logger logger = LoggerFactory.getLogger(FilterEngine.class);
    
    /**
     * Compile and set BPF filter on handle
     * @param handle Pcap handle
     * @param filterExpression BPF filter expression
     * @throws PcapNativeException if filter compilation fails
     * @throws NotOpenException if handle not open
     */
    public void compileFilter(PcapHandle handle, String filterExpression)
            throws PcapNativeException, NotOpenException {
        if (filterExpression == null || filterExpression.trim().isEmpty()) {
            logger.debug("Empty filter expression, skipping");
            return;
        }
        
        try {
            BpfProgram bpfProgram = handle.compileFilter(
                filterExpression,
                BpfProgram.BpfCompileMode.OPTIMIZE,
                PcapHandle.PCAP_NETMASK_UNKNOWN
            );
            
            handle.setFilter(bpfProgram);
            logger.info("[JShark] Filter successfully applied: {}", filterExpression);
            
        } catch (PcapNativeException e) {
            logger.error("Failed to compile filter: {}", filterExpression, e);
            throw new PcapNativeException("Invalid filter expression: " + filterExpression +
                                         ". Error: " + e.getMessage(), e);
        }
    }
}