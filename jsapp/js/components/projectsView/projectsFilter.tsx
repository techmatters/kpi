import React, {
  useState,
  useEffect,
} from 'react';
import clonedeep from 'lodash.clonedeep';
import bem, {makeBem} from 'js/bem';
import Button from 'js/components/common/button';
import KoboModal from 'js/components/modals/koboModal';
import KoboModalHeader from 'js/components/modals/koboModalHeader';
import type {ProjectsFilterDefinition} from './projectsViewConstants';
import ProjectsFilterEditor from './projectsFilterEditor';
import './projectsFilter.scss';

bem.ProjectsFilter = makeBem(null, 'projects-filter');
bem.ProjectsFilter__modalContent = makeBem(bem.ProjectsFilter, 'modal-content');
bem.ProjectsFilter__modalFooter = makeBem(bem.ProjectsFilter, 'modal-footer', 'footer');

interface ProjectsFilterProps {
  /** A list of existing filters (if any are defined). */
  filters: ProjectsFilterDefinition[];
  /**
   * When user clicks "apply" or "reset" button, the components will return
   * new filters.
   */
  onFiltersChange: (filters: ProjectsFilterDefinition[]) => void;
}

export default function ProjectsFilter(props: ProjectsFilterProps) {
  const getInitialFilters = () => {
    if (props.filters.length === 0) {
      return [{}];
    } else {
      return clonedeep(props.filters);
    }
  };

  console.log('ProjectsFilter', props);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [filters, setFilters] = useState(getInitialFilters());

  const toggleModal = () => {
    setIsModalOpen(!isModalOpen);
    // Reset filters when closing modal.
    if (isModalOpen === false) {
      setFilters(getInitialFilters());
    }
  };

  const addFilter = () => {
    console.log('add filter!');
    const newFilters = clonedeep(filters);
    newFilters.push({});
    setFilters(newFilters);
  };

  const applyFilters = () => {
    console.log('apply filters');
    // props.onFiltersChange(filters);
  };

  const resetFilters = () => {
    console.log('reset filters');
    // props.onFiltersChange(filters);
  };

  const onFilterEditorChange = (filterIndex: number, filter: ProjectsFilterDefinition) => {
    const newFilters = clonedeep(filters);
    newFilters[filterIndex] = filter;
    setFilters(newFilters);
  };

  const onFilterEditorDelete = (filterIndex: number) => {
    const newFilters = clonedeep(filters);
    newFilters.splice(filterIndex, 1);
    setFilters(newFilters);
  };

  const getTriggerLabel = () => {
    let outcome = t('filter');
    if (props.filters.length >= 1) {
      outcome += `&nbsp;(${props.filters.length})`;
    }
    return outcome;
  };

  return (
    <bem.ProjectsFilter>
      {/* Trigger button */}
      <Button
        type='bare'
        size='s'
        color='storm'
        onClick={toggleModal}
        startIcon='filter'
        label={getTriggerLabel()}
      />

      <KoboModal
        isOpen={isModalOpen}
        onRequestClose={toggleModal}
        size='medium'
      >
        <KoboModalHeader
          icon='filter'
          iconColor='storm'
          onRequestCloseByX={toggleModal}
        >
          {'Table filter'}
        </KoboModalHeader>

        <bem.ProjectsFilter__modalContent>
          {filters.map((filter, filterIndex) => (
            <ProjectsFilterEditor
              key={filterIndex}
              filter={filter}
              // We want the labels only for first editor.
              hideLabels={filterIndex !== 0}
              onFilterChange={(newFilter) => {onFilterEditorChange(filterIndex, newFilter);}}
              onDelete={() => {onFilterEditorDelete(filterIndex);}}
            />
          ))}

          {filters.length === 0 &&
            <p>{t('There are no filters, you can add one below')}</p>
          }
        </bem.ProjectsFilter__modalContent>

        <bem.ProjectsFilter__modalFooter>
          <Button
            type='bare'
            color='blue'
            size='m'
            onClick={addFilter}
            startIcon='plus'
            label={t('Add filter')}
          />

          <Button
            type='frame'
            color='storm'
            size='m'
            onClick={resetFilters}
            label={t('Reset')}
          />

          <Button
            type='frame'
            color='blue'
            size='m'
            onClick={applyFilters}
            label={t('Apply')}
          />
        </bem.ProjectsFilter__modalFooter>
      </KoboModal>
    </bem.ProjectsFilter>
  );
}
